# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4

from socket import *
from select import *
import json
import sys
import time
import logging
import base64
import os.path
from log import *
from server_client import *
from server_registry import *
from server_actions import *
from security import *
#from cc_pykcs11 import *
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
        # dictionary to manage order of arrival (indexed by socket)
        self.csocks = {}

        # to establish the diffie-hellman session key
        self.server_private = None
        self.server_public = None
        self.session_key_db = {}
        self.sk_lastKey = 1

        # asymmetric component
        self.private_key = getPrivRSA()
        self.public_key = getPubRSA(self.private_key)
        self.public_key_db = {}
        self.pk_lastKey = 1
        self.public_key_db[self.pk_lastKey] = []


    # Function to establish the session key between the server and the recently added server
    def server_session_key_establishment(self, csock):
        # Generate the private and public eliptic-curve keys
        self.server_private = privateKeyECDHE()
        self.server_public = publicKeyECDHE(self.server_private)
        
        # convert the public ECDHE to bytes in PEM format
        server_pubDH = self.server_public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        # obtain server's signature
        server_signature = sign_msg(self.private_key,server_pubDH)
        # send to the client the public key of ECDHE and the server's signature
        csock.send(bytes(json.dumps({"server_public": server_pubDH.decode('utf-8'), "signature": base64.b64encode(server_signature).decode('utf-8')})+TERMINATOR, 'utf-8'))

        # receives the client's public value
        client_rcvd = csock.recv(BUFSIZE)
        client_parsed = json.loads(client_rcvd.decode('utf-8'))
        client_public = serialization.load_pem_public_key(client_parsed['client_public'].encode('utf-8'), default_backend()) 
        client_signature = base64.b64decode(client_parsed['signature'])

        # obtain client's public key
        client_PK = serialization.load_pem_public_key(self.public_key_db[self.csocks[csock]].encode('utf-8'), default_backend())
        # verify the client's signature
        try:
            verify_sign(client_PK, client_signature, client_parsed['client_public'].encode('utf-8'))
        except Exception:
            log(logging.ERROR, "Signature is Invalid")
            self.delClient(csock)
            return None

        # Generating the session key and storing it in the
        # session key array
        self.session_key_db[self.sk_lastKey] = sessionKey(self.server_private,client_public)
        self.sk_lastKey += 1
        log(logging.DEBUG,"\nSession Key Database: {}\n".format(self.session_key_db))

    # Function to exchange the public keys between the server and the recently added server
    def exchange_public_key(self, csock):

        # Convert to bytes the client's Public Key
        pem = self.public_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        # Create the server's signature
        signature = sign_msg(self.private_key,pem)
        # Send server's public key to the recent added client
        csock.send(bytes(json.dumps({"public_key": pem.decode('utf-8'), "signature": base64.b64encode(signature).decode('utf-8')})+TERMINATOR, 'utf-8'))

        # Receives the client's public key
        client_rcvd = csock.recv(BUFSIZE)
        client_parsed = json.loads(client_rcvd.decode('utf-8'))
        client_public_key = client_parsed['public_key'].encode()
        client_signature = base64.b64decode(client_parsed['signature'].encode())

        try:
            verify_sign(serialization.load_pem_public_key(client_public_key,default_backend()), client_signature,client_public_key)
            log(logging.DEBUG,"Client's Public Key Received")
        except:
            log(logging.ERROR, "Signature is Invalid\n")
            delClient(csock)
            return None

        # Store the client's public key (in bytes) in the public key array
        self.public_key_db[self.pk_lastKey] = client_public_key.decode('utf-8')
        self.csocks[csock] = self.pk_lastKey
        self.pk_lastKey += 1
        log(logging.DEBUG,"\nPublic Key Database: {}\n".format(self.public_key_db))

        # Store the public keys in a file
        db = open("public_keys.pem","w")
        for i in self.public_key_db:
            if self.public_key_db[i] == []:
                db.write("Empty\n")
            else:
                db.write(str(self.public_key_db[i]))
        db.close()

    # Function to update the databases
    def update(self, s):

        # Checks for duplicate values
        for i in self.public_key_db:
            if self.public_key_db[i] == self.server_actions.updated_pK:
                self.public_key_db[i] = []
                break

        # Stores the session key in the correct place 
        for i in self.session_key_db:
            if self.session_key_db[i] == self.session_key_db[self.csocks[s]]:
                tmp = self.session_key_db[self.csocks[s]]
                self.session_key_db[i] = []
                self.session_key_db[self.server_actions.updated_id] = tmp
                break

        # Checks for duplicate values
        for i in self.csocks:
            if self.csocks[i] == self.server_actions.updated_id:
                self.csocks[i] = []
                break
              
        # Updates the databases  
        self.public_key_db[self.server_actions.updated_id] = self.server_actions.updated_pK
        self.csocks[s] = self.server_actions.updated_id
        self.server_actions.update = False

        # Store the public keys in a file
        db = open("public_keys.pem","w")
        for i in self.public_key_db:
            if self.public_key_db[i] == []:
                db.write("Empty\n")
            else:
                db.write(str(self.public_key_db[i]))
        db.close()


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
        self.exchange_public_key(csock)
        self.server_session_key_establishment(csock)
        
    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            log(logging.ERROR, "Client NOT deleted: %s not found" %
                self.clients[csock])
            return

        client = self.clients[csock]
        
        del self.clients[client.socket]
        self.public_key_db[self.csocks[csock]] = []
        self.session_key_db[self.csocks[csock]] = []
        self.csocks[csock] = []

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
                    if rest[-1] == 61 and rest[-2] == 61:
                        data += rest
                        break
                    else:
                        data += rest
                
            # decipher the received message using the established session key
            data = data.split(b'\n')
            
            msg = base64.b64decode(data[0])
            ctr = base64.b64decode(data[1])
            data = AES_decrypt(self.session_key_db[self.csocks[s]], ctr, msg)
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
                print(self.server_actions.update)
                # check for updates
                if self.server_actions.update == True:
                    self.update(s)
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
            msg = AES_encrypt(self.session_key_db[self.csocks[s]], ctr, client.bufout[:BUFSIZE])
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
