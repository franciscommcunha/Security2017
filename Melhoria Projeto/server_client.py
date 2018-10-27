import json
import sys
import logging
import msvcrt # for Windows users, uncomment  if necessary
import base64
import time
import glob
import datetime
import shutil
from log import *
from socket import *
from select import *
from security import *
from citizen_card import *
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

# https://stackoverflow.com/questions/33434007/python-socket-send-receive-messages-at-the-same-time

# Client address
HOST = ""   # All available interfaces
PORT = 8080  # The client port

TERMINATOR = "\r\n"
BUFSIZE = 512 * 1024
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30

class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.uuid = None
        self.dirname = "Saved Messages Box"
        self.order_arrival = None
        self.sa_data = None
        self.command = "" # for user command input
        self.enable_help = True # to enable/disable help command
        
        # to establish the diffie-hellman session key
        self.ecdhe_private = None
        self.ecdhe_public = None
        self.session_key = None

        # symmetric component
        self.shared_key = generate_symm()
        self.AEScipher = None
        
        # asymmetric component
        self.private_key = getPrivRSA()
        self.public_key = getPubRSA(self.private_key)
        self.CC_publicKey = None
        
        # citizen card
        self.cc = CitizenCard()

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s)" % (self.id, str(self.addr))

    def asDict(self):
        return {'id': self.id}

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""
        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d\n" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data.decode('utf-8')
        reqs = self.bufin.split(TERMINATOR)
        self.bufin = reqs[-1]
        return reqs[:-1]

    def sendResult(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)\n" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        #log(logging.INFO, "Client.close(%s)" % self)
        print("Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)\n" % self)

    def issueCreate(self, certificate, name):
        self.enable_help = False
        tipo = "create"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))

        # Retrive user's name from citizen card
        name = name.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Convert Public Key into PEM format
        pubKey = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Create signature
        signature = self.cc.sign(str(self.uuid)+name+str(pubKey))

        # Get the certificate's chain
        chain = self.cc.getChain(self.uuid, certificate)
        for i in chain:
            chain[chain.index(i)] = i.decode('utf-8')

        # Generate a random number for the CTR mode
        ctr = counterMode()

        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, 
            "uuid":self.uuid,
            "name": name,
            "pubKey": pubKey.decode(),
            "signature": base64.b64encode(signature).decode(),
            "certificate": certificate.decode(),
            "chain":chain})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueList(self):
        self.enable_help = False
        tipo = "list"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))

        try:
            uid = int(input("USER ID: "))
        except ValueError:
            log(logging.ERROR,"User ID must be a integer\n")
            return None

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, "id": uid})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueNew(self):
        self.enable_help = False
        tipo = "new"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, "id": self.id})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueAll(self):
        self.enable_help = False
        tipo = "all"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, "id": self.id})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueSend(self):
        self.enable_help = False
        tipo = "send"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))
        
        try:
            dst = int(input("DESTINATION ID: "))
        except ValueError:
            log(logging.ERROR,"Destinatio ID must be a integer\n")
            return None

        msg = input("MESSAGE TO SEND: ")
        if msg is None:
            log(logging.ERROR,"Message can't be empty\n")
            return None

        # Get certificate to sign
        cert_name, cert_ec = self.cc.getCert(self.uuid)
        # Get the certificate's chain
        chain = self.cc.getChain(self.uuid, cert_name)
        for i in chain:
            chain[chain.index(i)] = i.decode('utf-8')

        # Request receiver's public key
        dst_pubKey = self.request_PubKey(dst)
        if dst_pubKey is None:
            return None
        
        try:
	        # Generate a random number for the CTR mode
	        ctr = counterMode()

			# Cipher the message with the the symmetric key
	        c_msg = AES_encrypt(self.shared_key, ctr, msg)
	        
	        # Cipher the symmetric key with the receiver's public key
	        c_key = dst_pubKey.encrypt(self.shared_key, 
	            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
	                        algorithm=hashes.SHA256(),
	                        label=None))
	        
	        # Create the client's signature
	        signature = self.cc.sign(c_msg)
	        
	        # Cipher copy with the client's public key
	        copy = self.public_key.encrypt(msg.encode('utf-8'),
	            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
	                        algorithm=hashes.SHA256(),
	                        label=None))
        except:
        	log(logging.ERROR, "Couldn't send message, either it was too long or it didn't meet the requirements\n")

        # Generate a random number for the CTR mode
        sctr = counterMode()
        # Cipher the message with the session key
        smsg = AES_encrypt(self.session_key, sctr, json.dumps({
            "type": tipo, 
            "src": self.id, 
            "dst": dst, 
            "msg": base64.b64encode(c_msg).decode("utf-8"),
            "symkey": base64.b64encode(c_key).decode("utf-8"),
            "ctr": base64.b64encode(ctr).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
            "certificate": cert_name.decode("utf-8"),
            "chain": chain,
            "copy": base64.b64encode(copy).decode("utf-8")
        })+TERMINATOR)

        self.socket.send(base64.b64encode(smsg)+"\n".encode('utf-8')+base64.b64encode(sctr))

    def issueRecv(self):
        self.enable_help = False
        tipo = "recv"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))
        
        mid = input("MESSAGE ID: ")

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, "id": self.id, "msg": mid})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueReceipt(self,mid,msg):
        self.enable_help = False
        self.command = "receipt"
        tipo = "receipt"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))

        # Sign the deciphered message to signal it was read
        receipt = self.cc.sign(msg.encode('utf-8'))
        
        # Get certificate
        cert_name, cert_ec = self.cc.getCert(self.uuid)
        # Get the certificate's chain
        chain = self.cc.getChain(self.uuid, cert_name)
        for i in chain:
            chain[chain.index(i)] = i.decode('utf-8')
        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, 
            "id": self.id, 
            "msg": mid, 
            "receipt": base64.b64encode(receipt).decode('utf-8'),
            "certificate": cert_name.decode('utf-8'),
            "chain": chain})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueStatus(self):
        self.enable_help = False
        tipo = "status"
        #log(logging.DEBUG, "%s" % json.dumps(tipo))

        mid = str(input("RECEIPT ID: "))

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, "id":self.id, "msg":mid})+TERMINATOR)
        
        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    		
    def help(self):
        if self.enable_help == True:
            print("Usage: [option]\nOptions and arguments:\n\
                        list        : the server will reply with a message containing a list of users with a message box\n\
                        new         : the server will reply with a message containing a list of messages not yet read by the client\n\
                        all         : the server will reply with a message containing a list of all messages received by the user\n\
                        send        : send a message to another client\n\
                        recv        : receive a message from a client message box\n\
                        status      : check the status of a sent message (if it was seen or not)\n\
                        exit        : exit the program\n")

    def send_to_server(self):
        
        if self.command == "list":
            self.issueList()
        if self.command == "new":
            self.issueNew()
        if self.command == "all":
            self.issueAll()
        if self.command == "send":
            self.issueSend()
        if self.command == "recv":
           self.issueRecv()
        if self.command == "status":
            self.issueStatus()
        if self.command == "exit":
            self.close()
        else:
            self.help()

    def receive_from_server(self, data):
        self.enable_help = True

        data = data.split(b"\n")
        msg = base64.b64decode(data[0])
        ctr = base64.b64decode(data[1])
        data = AES_decrypt(self.session_key, ctr, msg)
        parsed = json.loads(data.decode('utf-8'))

        if self.command == "create":
            self.load_create(parsed)
        if self.command == "list":
            self.load_list(parsed)
        if self.command == "new":
            self.load_new(parsed)
        if self.command == "all":
            self.load_all(parsed)
        if self.command == "send":
            self.load_send(parsed)
        if self.command == "recv":
            self.load_recv(parsed)
        if self.command == "receipt":
            self.load_receipt(parsed)
        if self.command == "status":
            self.load_status(parsed)

    def load_create(self, parsed):

        try:
            self.id = parsed["result"]
            int(self.id)
            #log(logging.DEBUG, "USER ID: {}".format(self.id))
            print("User ID (given by the Server): {}\n".format(self.id))

            #renomear a pasta None para o nome do self.id
            old_dir = "client_certificates/None/"
            new_dir = "client_certificates/"+str(self.id)+"/"

            if os.path.exists(old_dir):
                os.rename(old_dir, new_dir)

            if not os.path.exists(self.dirname):
            	#log(logging.DEBUG,"\nCreating directory to store saved messages")
            	os.mkdir(self.dirname)

            self.dirname = os.path.join(self.dirname,str(self.uuid))
           
            if not os.path.exists(self.dirname):
            	#log(logging.DEBUG,"\nCreating directory to store saved messages for user {}".format(self.uuid))
            	os.mkdir(self.dirname)

        except Exception:
            log(logging.ERROR, "{}\n".format(parsed["error"]))
            sys.exit(1)

    def load_list(self, parsed):

        try:
            lst = parsed["result"]
        except KeyError:
            log(logging.ERROR,"Failed to obtain list of message boxes\n")
            return None
        
        if lst == None:
            log(logging.ERROR, "User doesn't exist\n")
        else:
            #log(logging.DEBUG, "USERS WITH MESSAGE BOX:")
            print("Users with Message Box:")
            for i in lst:
                for j in i:
                    #log(logging.DEBUG, "**{}: {}".format(j,i[j]))
                    if isinstance(i[j], dict):
                        for k in i[j]:
                            print("**{}: {}".format(k,i[j][k]))
                    else:
                        print("**{}: {}".format(j,i[j]))

        print("\n")

    def load_new(self, parsed):

        message_identifiers = parsed["result"]
        for mid in message_identifiers:
            if "_scs" in mid:
                message_identifiers.remove(mid)
        
        #log(logging.DEBUG, "NEW MESSAGES: %s" % (message_identifiers))    
        print("New Messages: {}\n".format(message_identifiers))

    def load_all(self, parsed):

        received_messages = parsed["result"][0]
        for mid in received_messages:
            if "_scs" in mid:
                received_messages.remove(mid)
        sent_messages = parsed["result"][1]
        for mid in sent_messages:
            if "_scs" in mid:
                sent_messages.remove(mid)

        #log(logging.DEBUG, "RECEIVED MESSAGES: %s SENT MESSAGES: %s" % (received_messages, sent_messages))
        print("Received Messages: {}".format(received_messages))
        print("Sent Messages: {}\n".format(sent_messages))

    def load_send(self,parsed):

        try:
            lst = parsed["result"]
        except KeyError:
            log(logging.ERROR,"{}\n".format(parsed["error"]))
            return None

        #log(logging.DEBUG,"MESSAGE {} SUCCESSFULLY SENT TO USER. RECEIPT {} SAVED".format(lst[0],lst[1]))
        print("Message {} Successfully Sent. Receipt {} Saved.\n".format(lst[0],lst[1]))

    def load_recv(self,parsed):

        try:
            lst = parsed["result"]
        except Exception:
            log(logging.ERROR,"{}\n".format(parsed["error"]))
            return None
    
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, lst[5].encode())
        chain = [v for v in lst[6].values()]
        
        #verify the certificate
        try:
            self.cc.verify(certificate, chain)
            #log(logging.DEBUG, "Certificate is valid\n")
        except Exception as e:
            log(logging.ERROR, e)
            return None
        # Verify the sender's signature
        try:
            crypto.verify(certificate,base64.b64decode(lst[4]),base64.b64decode(lst[1]),"SHA256")
            #log(logging.DEBUG, "Signature is Valid")
        except Exception as e:
            log(logging.ERROR, e)
            return None

        try:
            # Decipher the symmetric key
            symmKey = self.private_key.decrypt(base64.b64decode(lst[2]),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                            algorithm=hashes.SHA256(),
                            label=None))
        except Exception as e:
            log(logging.ERROR, e)
            return None

        # Decipher the message
        ctr = base64.b64decode(lst[3].encode())
        msg = base64.b64decode(lst[1].encode())
        d_msg = AES_decrypt(symmKey,ctr,msg).decode('utf-8')
        #log(logging.DEBUG,"SENDER ID: {}".format(lst[0]))
        print("Sender ID: {}".format(lst[0]))
        #log(logging.DEBUG,"MESSAGE:   {}".format(d_msg))
        print("Message: {}".format(d_msg))

        while True:
            save = str(input("Save message?(y/n): "))
            if save == 'y':
            # Save deciphered message
                try:
                    with open(os.path.join(self.dirname,str(lst[7])),"w") as f:
                        f.write(d_msg)
                    print("Message saved successfully\n")
                except Exception as e:
                    log(logging.ERROR, e)
                # Send the receipt after reading the message
                self.issueReceipt(lst[7],d_msg)
                break
            elif save == 'n':
            	print("\n")
            	# Send the receipt after reading the message
            	self.issueReceipt(lst[7],d_msg)
            	break
            else:
            	print("Invalid input\n")

    def load_receipt(self,parsed):

        try:
            lst = parsed["result"]
        except Exception:
            log(logging.ERROR,"{}\n".format(parsed["error"]))
            return None

    def load_status(self,parsed):

        try:
            lst = parsed["result"]
        except KeyError:
            log(logging.ERROR,"{}\n".format(parsed["error"]))
            return None
        
        c_copy = lst["msg"]
        copy = self.private_key.decrypt(base64.b64decode(c_copy),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                        algorithm=hashes.SHA256(),
                        label=None))
        #log(logging.DEBUG,"MESSAGE: {}".format(copy.decode('utf-8')))
        print("Message: {}".format(copy.decode('utf-8')))
        rec = lst["receipts"]
        if rec == []:
            log(logging.ERROR,"Receipts not Found\n")
            return None
        #log(logging.DEBUG, "RECEIPTS:")
        print("Status of the message:")
        tmp_id = None
        for i in rec:
            for j in i:
                if j == "receipt":
                    r = i[j].split("\n")
                    certs = {}
                    k = 0
                    certs[k] = ""
                    for l in r[1:]:
                        certs[k] += l+"\n"
                        if i == "-----END CERTIFICATE-----":
                            k += 1
                            certs[k] = ""
                    chain = [v for v in certs.values()]
                    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certs[0])
                    #verify the certificate
                    try:
                        self.cc.verify(certificate, chain)
                        #log(logging.DEBUG, "Certificate is valid\n")
                    except Exception as e:
                        log(logging.ERROR, e)
                        return None
                    # Verify the sender's signature
                    try:
                        crypto.verify(certificate,base64.b64decode(r[0]),copy,"SHA256")
                        #log(logging.DEBUG,"**{}: Signature is Valid".format(j))
                        print("**{}: Signature is Valid".format(j))
                        print("------")
                    except:
                        #log(logging.DEBUG,"**{}: Signature is not Valid".format(j))
                        print("**{}: Signature is Invalid".format(j))
                        print("------")
                else:
                    #log(logging.DEBUG,"**{}: {}".format(j,i[j]))
                    print("**{}: {}".format(j,i[j]))

    def loop(self):
        while True:
          
            # Wait for input from socket & stdin
            # Linux and Mac version
            #issues = select([sys.stdin, self.socket],[],[])[0]
            
            # Windows version
            # https://stackoverflow.com/questions/34252774/winerror-10038-alternatives-to-sys-stdin-on-windows
            issues = select([self.socket],[],[],1)[0]
            if msvcrt.kbhit():
                issues.append(sys.stdin)
            
            for issue in issues:
                if issue == socket: # message from the server

                    data = self.socket.recv(BUFSIZE)
                    if data[-1] != 61 and data[-2] != 61:
                    	while 1:
                    		rest = self.socket.recv(BUFSIZE)
                    		data += rest
                    		if rest[-1] == 61 and rest[-2] == 61:
                    			break
                    self.receive_from_server(data)
                    
                    if not data: 
                        print("Disconnected")
                        sys.exit(0)

                else: # user enters a message
                	self.command = input(">>>")
	                self.send_to_server()

    # method to establish the session key using Diffie-Hellman algorihtm
    def session_key_establishment(self, cert):
        # Generate the private and public eliptic-curve keys
        self.ecdhe_private = privateKeyECDHE()
        self.ecdhe_public = publicKeyECDHE(self.ecdhe_private)
        
        # receives the server's public value
        server_rcvd = socket.recv(BUFSIZE)
        server_parsed = json.loads(server_rcvd.decode('utf-8'))
        # Server's ECDHE public value
        server_public = serialization.load_pem_public_key(server_parsed['server_public'].encode('utf-8'), default_backend())
        # Server's signature (message + private key)
        server_signature = base64.b64decode(server_parsed['signature'].encode())
        # Server's certificate
        server_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, server_parsed['certificate'].encode())
        
        # verify the message's validity
        # http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/
        # verify the self-signed certificate
        try:
            self.cc.verify(server_certificate,[])
            #log(logging.DEBUG, "Certificate is valid\n")
        except Exception:
            log(logging.ERROR, "Invalid Certificate, program will terminate\n")
            sys.exit(1)
        # verify the signature
        try:
            # convert the certificate into cryptography.x509.Certificate object
            server_certificate = server_certificate.to_cryptography()
            verify_sign(server_certificate.public_key(), server_signature, server_parsed['server_public'].encode('utf-8'))
            #log(logging.DEBUG, "Signature is valid\n")
        except Exception as e:
        	log(logging.ERROR, "Invalid Signature, program will terminate\n")
        	sys.exit(1)

        # convert the public ECDHE to bytes in PEM format
        client_pubDH = self.ecdhe_public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        # get Certificate Chains
        chain = self.cc.getChain(self.uuid, cert)
        for i in chain:
            chain[chain.index(i)] = i.decode('utf-8')
        # create the client's signature (Citizen Card private key + data)
        client_signature = self.cc.sign(client_pubDH)
        # sends the public value to the server
        socket.send(bytes(json.dumps({"client_public": client_pubDH.decode('utf-8'), 
        	"signature": base64.b64encode(client_signature).decode('utf-8'),
        	"certificate": cert.decode('utf-8'),
            "chain": chain})+TERMINATOR, 'utf-8'))

        # Generating the session key
        try:
            self.session_key = sessionKey(self.ecdhe_private, server_public)
            server_rcvd = socket.recv(BUFSIZE)
            server_parsed = json.loads(server_rcvd.decode('utf-8'))
            if "error" in server_parsed.keys():
                raise Exception(server_parsed["error"])
            else:
                #log(logging.DEBUG,"Session Key SUCCESSFULLY ESTABLISHED\n")
                print("Secure Connection Established\n")
        except Exception as e:
            log(logging.ERROR, e)
            sys.exit(1)

    # request target's public key
    def request_PubKey(self, dst):
        tipo = "recPK"
        
        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.session_key, ctr, json.dumps({"type": tipo, "dst": dst})+TERMINATOR)

        # Request the public key
        socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

        # Receive the public key
        server_rcvd = socket.recv(BUFSIZE)
        server_rcvd = server_rcvd.split(b"\n")
        msg = base64.b64decode(server_rcvd[0])
        ctr = base64.b64decode(server_rcvd[1])
        server_rcvd = AES_decrypt(self.session_key, ctr, msg)
        server_parsed = json.loads(server_rcvd.decode('utf-8'))
        
        try:
	        rec_PK = serialization.load_pem_public_key(server_parsed["publicKey"].encode('utf-8'),default_backend())
        except:
        	log(logging.ERROR, "{}\n".format(server_parsed["error"]))
        	return None

        if rec_PK is None:
            log(logging.ERROR,"User's Public Key couldn't be retrieved\n")
            return None
        #else:
            #log(logging.DEBUG,"User's Public Key SUCCESSFULLY RECEIVED")

        return rec_PK
        



if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    client = None

    try:
        #log(logging.INFO, "Starting Secure IM Client v1.0")
        print("Starting Secure IM Client v1.0")
        socket = socket(AF_INET, SOCK_STREAM)
        addr = '127.0.0.1'
        client = Client(socket, addr)
        socket.connect((addr, PORT))
        #log(logging.INFO, "Secure IM client connected on %s\n" %
        #    str(socket.getsockname()))
        print("Secure IM client connected on %s\n" % str(socket.getsockname()))

        try:
            client.cc.citizen_card_detected()
            client.cc.extract_certificates(None)
            cert_name, cert_ec = client.cc.getCert(None)
            certificate_name = x509.load_pem_x509_certificate(cert_name, default_backend())
            certificate_sign = x509.load_pem_x509_certificate(cert_ec, default_backend())
            client.uuid = int.from_bytes(client.cc.get_digest(certificate_name),byteorder = "big")
            #log(logging.DEBUG, "User Universal Id: {}\n".format(client.uuid))
            print("User Universal Id: {}\n".format(client.uuid))
            client.cc.extract_certificates(client.uuid)
            #shutil.rmtree("client_certificates/None")
            # Windows Version
            shutil.rmtree("client_certificates\\None")
            client.CC_publicKey = client.cc.get_PublicKey(certificate_sign)
        	# establishing the session key between client and server
            client.session_key_establishment(cert_name)
            # send create message
            client.issueCreate(cert_name, certificate_name)
            client.command = "create"
        except Exception as e:
        	log(logging.ERROR, e)
        	sys.exit(1)

        while True:
            try:
                client.loop()
            except KeyboardInterrupt:
                client.close()
                #log(logging.INFO, "CTRL-C pressed: Quitting!")
                print("CTRL-C pressed: Quitting!")
                break
    except:
        logging.exception("Client ERROR")
        if client is not (None):
            client.close()
