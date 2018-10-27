# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4

import json
import sys
import time
import logging
import base64
import os.path
from socket import *
from select import *
from log import *
from server_client import *
from server_registry import *
from server_actions import *
from security import *
from certificates import *
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024


class Server:

    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        log(logging.INFO, "Secure IM server listening on %s" %
            str(self.ss.getsockname()))

        self.registry = ServerRegistry()
        self.server_actions = ServerActions()

        # clients to manage (indexed by socket and by name):
        self.clients = {}       # clients (key is socket)
        
        # to establish the diffie-hellman session key
        self.ecdhe_private = None
        self.ecdhe_public = None
        self.session_key_db = {}
        
        # asymmetric component
        self.private_key = getPrivRSA()
        self.public_key = getPubRSA(self.private_key)
        
        self.certs = Certificates()
        self.certs.createSelfSignedCert(self.public_key, self.private_key)

    # Function to establish the session key between the server and the recently added server
    def session_key_establishment(self, csock):
        # Generate the private and public eliptic-curve keys
        self.ecdhe_private = privateKeyECDHE()
        self.ecdhe_public = publicKeyECDHE(self.ecdhe_private)
        
        # convert the public ECDHE to bytes in PEM format
        server_pubDH = self.ecdhe_public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        # send to the client the public key of ECDHE and the server's signature
        csock.send(bytes(json.dumps({"server_public": server_pubDH.decode('utf-8'), 
            "signature": base64.b64encode(sign_msg(self.private_key,server_pubDH)).decode('utf-8'),
            'certificate': self.certs.getCert().decode()})+TERMINATOR, 'utf-8'))

        # receives the client's public value
        client_rcvd = csock.recv(BUFSIZE)
        client_parsed = json.loads(client_rcvd.decode('utf-8'))
        # Client's ECDHE public value
        client_public = serialization.load_pem_public_key(client_parsed['client_public'].encode('utf-8'), default_backend()) 
        # Client's signature (message + private key)
        client_signature = base64.b64decode(client_parsed['signature'])
        # Client's certificate
        client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, client_parsed['certificate'].encode())
        # Client's certificate chain
        client_chain = client_parsed['chain']
        
        # verify the client's certificate
        try:
            self.certs.verify(client_certificate, client_chain)
        except Exception as e:
            log(logging.ERROR, e)
            csock.send(bytes(json.dumps({"error": "Certificate is Invalid\n"})))
            self.delClient(csock)
            return None
        # verify the client's signature
        try:
            crypto.verify(client_certificate,bytes(client_signature),client_parsed['client_public'].encode(),"SHA256")
            log(logging.DEBUG, "Signature is Valid\n")
        except Exception as e:
            log(logging.ERROR, e)
            csock.send(bytes(json.dumps({"error": "Signature is Invalid\n"})))
            self.delClient(csock)
            return None

        # Generating the session key and storing it in the session key array
        try:
            self.session_key_db[csock] = sessionKey(self.ecdhe_private,client_public)
            log(logging.DEBUG,"\nSession Key Database: {}\n".format(self.session_key_db))
            csock.send(bytes(json.dumps({"result": 'OK'})+TERMINATOR, 'utf-8'))
        except Exception as e:
            log(logging.ERROR, e)
            csock.send(bytes(json.dumps({"error": "A problem was found during the calculation of the session key\n"})))

    def stop(self):
        """ Stops the server closing all sockets
        """
        log(logging.INFO, "Stopping Server")
        try:
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            log(logging.ERROR, "Client NOT Added: %s already exists" %
                self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        log(logging.DEBUG, "Client added: %s" % client)

        # Initiate session establishment
        self.session_key_establishment(client.socket)
        
    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            log(logging.ERROR, "Client NOT deleted: %s not found" %
                self.clients[csock])
            return

        client = self.clients[csock]
        
        del self.clients[client.socket]
        del self.session_key_db[client.socket]
        
        client.close()
        log(logging.DEBUG, "Client deleted: %s" % client)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            if data[-1] != 61 and data[-2] != 61:
                while 1:
                    rest = s.recv(BUFSIZE)
                    data += rest
                    if rest[-1] == 61 and rest[-2] == 61:
                        break
                
            # decipher the received message using the established session key
            data = data.split(b'\n')
            msg = base64.b64decode(data[0])
            ctr = base64.b64decode(data[1])
            data = AES_decrypt(self.session_key_db[s], ctr, msg)
            log(logging.DEBUG,
                "Received data from %s. Message:\n%r" % (client, data))
        except:
            logging.exception("flushin: recv(%s)" % client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.server_actions.handleRequest(s, req, self.clients[s])
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            return

        client = self.clients[s]

        try:
            ctr = counterMode()
            msg = AES_encrypt(self.session_key_db[s], ctr, client.bufout[:BUFSIZE])
            sent = client.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))
            log(logging.DEBUG, "Sent %d bytes to %s. Message:\n%r" %
                (sent, client, client.bufout[:sys.getsizeof(bytes(client.bufout[:BUFSIZE], 'utf-8'))]))
            # leave remaining to be sent later
            client.bufout = client.bufout[sys.getsizeof(bytes(client.bufout[:BUFSIZE], 'utf-8')):]
        except:
            logging.exception("flushout: send(%s)", client)
            logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open
            # client connection)
            rlist = [self.ss] + list(self.clients)

            # sockets to select for writing: (those that have something in
            # bufout)
            wlist = [sock for sock in self.clients if len(
                self.clients[sock].bufout) > 0]

            (rl, wl, xl) = select(rlist, wlist, rlist)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    log(logging.ERROR,
                        "Incoming, but %s not in clients anymore" % s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    log(logging.ERROR,
                        "Outgoing, but %s not in clients anymore" % s)

            for s in xl:
                log(logging.ERROR, "EXCEPTION in %s. Closing" % s)
                self.delClient(s)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    
    serv = None
    while True:
        try:
            log(logging.INFO, "Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)

            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                log(logging.INFO, "Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                log(logging.INFO, "CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
