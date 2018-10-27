from log import *
from socket import *
from select import *
from security import *
from cc_pykcs11 import * 
import json
import sys
import logging
#import msvcrt # for Windows users, uncomment  if necessary
import base64
import getpass
import time
import glob
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

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
        self.order_arrival = None
        self.sa_data = None
        self.command = "" # for user command input
        self.enable_help = True # to enable/disable help command
        self.logged_in = False
        self.dirname = "saved_msgs"
        
        # to establish the diffie-hellman session key
        self.client_private = None
        self.client_public = None
        self.client_session_key = None

        # symmetric component
        self.shared_key = generate_symm()
        self.AEScipher = None
        
        # asymmetric component
        self.private_key = getPrivRSA()
        self.public_key = getPubRSA(self.private_key)
        self.server_pubKey = None

        # citizen card
        self.cc = citizen_card() # object for citizen card class

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
            log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
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
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        log(logging.INFO, "Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)" % self)

    def issueCreate(self):
        self.enable_help = False

        tipo = "create"

        # client cannot create account without citizen card
        assert self.cc.citizen_card_detected() 

        self.cc.save_certificates(self.id) # saves the citizen card certicates

        attribs = self.cc.get_cert_attributes()
        attributes = attribs[0]

        log(logging.DEBUG, "%s" % json.dumps(tipo))

        try:
            for file in glob.glob('client_certificates/'+str(self.id)+'/EC de Autenticação do Cartão de Cidadão*.cer'):
                spt = file.split('/')
                cert_name = spt[-1]
            
            #Linux & Mac   
            cert = open("client_certificates/"+str(self.id)+"/"+cert_name, "rb").read()
            #Windows
            #cert = open("client_certificates\\"+cert_name, "rb").read()
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            
            #self.uuid = int(input("UUID: "))
            self.uuid = int(self.cc.get_digest_pub_key(certificate))
            log(logging.DEBUG, "%s" % json.dumps(self.uuid))

        except ValueError:
            log(logging.ERROR,"USER UNIVERSAL ID MUST BE A INTEGER")
            log(logging.ERROR,"USER UNIVERSAL ID NOT VALID")
            return None

        digest = hashes.Hash(hashes.BLAKE2s(32), backend = default_backend())
        digest.update(getpass.getpass("Password: ").encode('utf-8'))
        password = digest.finalize()
        
        to_sign = str(self.uuid)+"_"+str(password)

        signature = self.cc.sign(to_sign).decode() # bytes

        # Generate a random number for the CTR mode
        ctr = counterMode()

        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "uuid":self.uuid, 
            "pass": base64.b64encode(password).decode('utf-8'), 
            "signature": signature, 
            "to_sign": to_sign, 
            "cert_attributes": attributes})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueList(self):
        self.enable_help = False

        tipo = "list"

        log(logging.DEBUG, "%s" % json.dumps(tipo))

        try:
            uid = int(input("USER ID: "))
        except ValueError:
            log(logging.ERROR,"USER ID MUST BE A INTEGER")
            return None

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "id": uid})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueNew(self):
        self.enable_help = False

        # preciso verificar o id do cliente automaticamente??? Penso que sim, faz mais sentido
        tipo = "new"

        log(logging.DEBUG, "%s" % json.dumps(tipo))

        #self.id = int(input("NEW Introduza o seu ID: ")) # solucao temporaria

        print("ID func issueNew: {}".format(self.id))
        
        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "id": self.id})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueAll(self):
        self.enable_help = False

        tipo = "all"

        log(logging.DEBUG, "%s" % json.dumps(tipo))

        print("ID func issueAll: {}".format(self.id))
        
        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "id": self.id})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueSend(self):
        self.enable_help = False

        tipo = "send"

        log(logging.DEBUG, "%s" % json.dumps(tipo))
        
        try:
            dst = int(input("DESTINATION ID: "))
        except ValueError:
            log(logging.ERROR,"DESTINATION ID MUST BE A INTEGER")
            return None

        msg = input("MESSAGE TO SEND: ")

        # Request receiver's public key
        rec_pubKey = self.request_PubKey(dst)

        if rec_pubKey is None:
            return None
        
        try:
	        # Generate a random number for the CTR mode
	        ctr = counterMode()

			# Cipher the message with the the symmetric key
	        c_msg = AES_encrypt(self.shared_key, ctr, msg)
	        
	        # Cipher the symmetric key with the receiver's public key
	        c_key = rec_pubKey.encrypt(self.shared_key, 
	            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
	                        algorithm=hashes.SHA256(),
	                        label=None))
	        
	        # Create the client's signature
	        signature = sign_msg(self.private_key,c_msg)
	        
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
        smsg = AES_encrypt(self.client_session_key, sctr, json.dumps({
            "type": tipo, 
            "src": self.id, 
            "dst": dst, 
            "msg": base64.b64encode(c_msg).decode("utf-8"),
            "copy": base64.b64encode(copy).decode("utf-8"), 
            "symkey": base64.b64encode(c_key).decode("utf-8"),
            "ctr": base64.b64encode(ctr).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8")
        })+TERMINATOR)

        self.socket.send(base64.b64encode(smsg)+"\n".encode('utf-8')+base64.b64encode(sctr))

    def issueRecv(self):
        self.enable_help = False

        tipo = "recv"

        log(logging.DEBUG, "%s" % json.dumps(tipo))
        
        mid = input("MESSAGE ID: ")

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "id": self.id, "msg": mid})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueReceipt(self,mid,msg):
        self.enable_help = False

        self.command = "receipt"

        tipo = "receipt"
        
        message = mid

        # Sign the deciphered message to signal it was read
        receipt = sign_msg(self.private_key,msg.encode('utf-8'))
        
        log(logging.DEBUG, "%s" % json.dumps(tipo))

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "id": self.id, "msg": message, "receipt": base64.b64encode(receipt).decode('utf-8')})+TERMINATOR)

        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueStatus(self):
        self.enable_help = False

        tipo = "status"

        log(logging.DEBUG, "%s" % json.dumps(tipo))

        mid = str(input("RECEIPT ID: "))

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "id":self.id, "msg":mid})+TERMINATOR)
        
        self.socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

    def issueLogin(self):
        tipo = "login"

        try:
            self.uuid = int(input("User Universal Identification: "))
        except:
            log(logging.ERROR, "User Universal Identification must be an integer")
            return None

        digest = hashes.Hash(hashes.BLAKE2s(32), backend = default_backend())
        digest.update(getpass.getpass("Password: ").encode('utf-8'))
        password = digest.finalize()

        to_sign = str(self.uuid)+"_"+str(password)
        signature = self.cc.sign(to_sign).decode() # bytes

        # Generate a random number for the CTR mode
        ctr = counterMode()

        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "uuid": self.uuid, 
            "pass": base64.b64encode(password).decode('utf-8'), 
            "signature":signature, 
            "to_sign": to_sign})+TERMINATOR)
    	
        # Send the login parameters
        socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))
    	
        # Receive response
        data = self.socket.recv(BUFSIZE)
        data = data.split(b"\n")
        msg = base64.b64decode(data[0])
        ctr = base64.b64decode(data[1])
        data = AES_decrypt(self.client_session_key, ctr, msg)
        parsed = json.loads(data.decode('utf-8'))

        try:
            pwd = base64.b64decode(parsed["pass"])
            #Checks if the password is correct
            if password == pwd:
                self.logged_in = True
                self.id = parsed["id"]
                int(self.id)
                log(logging.DEBUG, "Login Successful")
                log(logging.DEBUG, "USER ID: {}".format(self.id))
                #Updates the public key in the server datatabase
                pK = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                # Generate a random number for the CTR mode
                ctr = counterMode()
                # Cipher the message with the session key
                msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": "update", "id": self.id, "public_key": pK.decode('utf-8'), 
                    "signature": base64.b64encode(sign_msg(self.private_key, pK)).decode('utf-8')})+TERMINATOR)
                # Send the update parameters
                socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))
                # Update dirname to save messages
                self.dirname = os.path.join(self.dirname,str(self.uuid))
            else:
                self.logged_in = False
                log(logging.ERROR, "ERROR: password doesn't match")
        except:
            self.logged_in = False
            log(logging.ERROR, "ERROR: {}".format(parsed['error']))
    		
    def help(self):
        if self.enable_help == True:
            print("\nUsage: [option]\nOptions and arguments:\n\
                        list        : the server will reply with a message containing a list of users with a message box\n\
                        new         : the server will reply with a message containing a list of messages not yet read by the client\n\
                        all         : the server will reply with a message containing a list of all messages received by the user\n\
                        send        : send a message to another client\n\
                        recv        : receive a message from a client message box\n\
                        status      : check the status of a sent message (if it was seen or not)\n")

    def send_to_server(self):
        
        if self.command == "create":
            self.issueCreate()
        if self.command == "list":
            self.issueList()
        elif self.command == "new":
            self.issueNew()
        elif self.command == "all":
            self.issueAll()
        elif self.command == "send":
            self.issueSend()
        if self.command == "recv":
           self.issueRecv()
        if self.command == "status":
            self.issueStatus()
        if self.command == "login":
        	self.issueLogin()
        else:
            self.help()

    def receive_from_server(self, data):
        self.enable_help = True

        data = data.split(b"\n")
        msg = base64.b64decode(data[0])
        ctr = base64.b64decode(data[1])
        data = AES_decrypt(self.client_session_key, ctr, msg)
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
            log(logging.DEBUG, "USER ID: {}".format(self.id))

            #renomear a pasta None para o nome do self.id
            old_dir = "client_certificates/None/"
            new_dir = "client_certificates/"+str(self.id)+"/"

            if os.path.exists(old_dir):
                os.rename(old_dir, new_dir)

            if not os.path.exists(self.dirname):
            	logging.debug("\nCreating directory to store saved messages")
            	os.mkdir(self.dirname)

            self.dirname = os.path.join(self.dirname,str(self.uuid))
           
            if not os.path.exists(self.dirname):
            	logging.debug("\nCreating directory to store saved messages for user {}".format(self.uuid))
            	os.mkdir(self.dirname)

            self.logged_in = True

        except Exception:
            log(logging.ERROR, "ERROR: {}".format(parsed["error"]))

    def load_list(self, parsed):

        try:
            lst = parsed["result"]
        except KeyError:
            log(logging.ERROR,"FAILED TO OBTAIN LIST OF MESSAGE BOXES")
            return None
        if lst == None:
            log(logging.DEBUG, "USER DOES NOT EXIST")
        else:
            log(logging.DEBUG, "USERS WITH MESSAGE BOX:")
            if len(lst) == 1:
                i = lst[0]
                if "uuid" in i:
                    log(logging.DEBUG, "**UUID: {}".format(i["uuid"]))
                else:
                    dec = i["description"]
                    log(logging.DEBUG, "**USER ID: {}".format(i["id"]))
                    log(logging.DEBUG, "**USER DESCRIPTION:")
                    for j in dec:
                        log(logging.DEBUG, "-----{}: {}".format(j,dec.get(j)))
            else:
                for i in lst:
                    log(logging.DEBUG, "**UUID: {}".format(i["uuid"]))

    def load_new(self, parsed):

        message_identifiers = parsed["result"]
        for mid in message_identifiers:
            if "_scs" in mid:
                message_identifiers.remove(mid)
        
        log(logging.DEBUG, "NEW MESSAGES: %s" % (message_identifiers))    
        
    def load_all(self, parsed):

        received_messages = parsed["result"][0]
        for mid in received_messages:
            if "_scs" in mid:
                received_messages.remove(mid)
        sent_messages = parsed["result"][1]
        for mid in sent_messages:
            if "_scs" in mid:
                sent_messages.remove(mid)

        log(logging.DEBUG, "RECEIVED MESSAGES: %s SENT MESSAGES: %s" % (received_messages, sent_messages))

    def load_send(self,parsed):

        try:
            lst = parsed["result"]
        except KeyError:
            log(logging.ERROR,"ERROR: {}".format(parsed["error"]))
            return None

        log(logging.DEBUG,"MESSAGE {} SUCCESSFULLY SENT TO USER. RECEIPT {} SAVED".format(lst[0],lst[1]))

    def load_recv(self,parsed):

        try:
            lst = parsed["result"]
        except Exception:
            log(logging.ERROR,"ERROR: {}".format(parsed["error"]))
            return None

        # Verify the sender's signature
        try:
            verify_sign(self.request_PubKey(lst[0]),base64.b64decode(lst[4].encode()),base64.b64decode(lst[1].encode()))
            log(logging.DEBUG, "SIGNATURE IS VALID")
        except Exception:
            log(logging.ERROR, "INVALID SIGNATURE")
            return None

        # Decipher the symmetric key
        symmKey = self.private_key.decrypt(base64.b64decode(lst[2]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                        algorithm=hashes.SHA256(),
                        label=None))
        # Decipher the message
        ctr = base64.b64decode(lst[3].encode())
        msg = base64.b64decode(lst[1].encode())
        d_msg = AES_decrypt(symmKey,ctr,msg).decode('utf-8')
        log(logging.DEBUG,"SENDER ID: {}".format(lst[0]))
        log(logging.DEBUG,"MESSAGE:   {}".format(d_msg))
        while True:
	        save = str(input("Save message?(y/n): "))
	        if save == 'y':
                # Save deciphered message
	        	with open(os.path.join(self.dirname,str(lst[5])),"w") as f:
	        		f.write(d_msg)
	        	# Send the receipt after reading the message
	        	self.issueReceipt(lst[5],d_msg)
	        	break
	        elif save == 'n':
	        	# Send the receipt after reading the message
	        	self.issueReceipt(lst[5],d_msg)
	        	break
	        else:
	        	print("Invalid input\n")

    def load_receipt(self,parsed):

        try:
            lst = parsed["result"]
        except Exception:
            log(logging.ERROR,"ERROR: {}".format(parsed["error"]))
            return None

    def load_status(self,parsed):

        try:
            lst = parsed["result"]
        except KeyError:
            log(logging.ERROR,"ERROR: {}".format(parsed["error"]))
            return None
        c_copy = lst["msg"]
        copy = self.private_key.decrypt(base64.b64decode(c_copy),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                        algorithm=hashes.SHA256(),
                        label=None))
        log(logging.DEBUG,"MESSAGE: {}".format(copy.decode('utf-8')))
        rec = lst["receipts"]
        if rec == []:
            log(logging.ERROR,"Receipts not Found")
            return None
        log(logging.DEBUG, "RECEIPTS:")
        tmp_id = None
        for i in rec:
	        for j in i:
	        	if j == "id":
	        		tmp_id = i[j]
	        		log(logging.DEBUG,"**{}: {}".format(j,i[j]))
	        	elif j == "receipt":
	        		pK = self.request_PubKey(tmp_id)
	        		try:
	        			verify_sign(pK,base64.b64decode(i[j]),copy)
	        			log(logging.DEBUG,"**{}: Signature is Valid".format(j))
	        		except:
	        			log(logging.DEBUG,"**{}: Signature is not Valid".format(j))
	        	else:
	        		log(logging.DEBUG,"**{}: {}".format(j,i[j]))

    def loop(self):
        while True:
          
            # Wait for input from socket & stdin
            # Linux and Mac version
            issues = select([sys.stdin, self.socket],[],[])[0]
            
            # Windows version
            # https://stackoverflow.com/questions/34252774/winerror-10038-alternatives-to-sys-stdin-on-windows
            """
            issues = select([self.socket],[],[],1)[0]
            if msvcrt.kbhit():
                issues.append(sys.stdin)
            """
            
            for issue in issues:
                if issue == socket: # message from the server

                    data = self.socket.recv(BUFSIZE)
                    self.receive_from_server(data)
                    
                    if not data: 
                        print("Disconnected")
                        sys.exit()

                else: # user enters a message
                	# checks if user is logged in
                	if self.logged_in == False:
                		print("\nUsage: [option]\nOptions and arguments:\n\
                				create 	: create a user message box. The server will respond with an internal indentifier\n\
                				login 	: login with an existing account\n")
                		self.command = input()
                		while self.command != "create" and self.command != "login":
                			print("Wrong input\n")
                			self.command = input()
                		self.send_to_server()
                	else:
	                	self.command = input()
	                	self.send_to_server()

    # method to establish the session key using Diffie-Hellman algorihtm
    def client_session_key_establishment(self):
        # Generate the private and public eliptic-curve keys
        self.client_private = privateKeyECDHE()
        self.client_public = publicKeyECDHE(self.client_private)
        
        # receives the server's public value
        server_rcvd = socket.recv(BUFSIZE)
        server_parsed = json.loads(server_rcvd.decode('utf-8'))
        server_public = serialization.load_pem_public_key(server_parsed['server_public'].encode('utf-8'), default_backend())
        server_signature = base64.b64decode(server_parsed['signature'])
        
        # verify the server's signature
        try:
        	verify_sign(self.server_pubKey,server_signature,server_parsed['server_public'].encode('utf-8'))
        except Exception:
            log(logging.ERROR, "Received Invalid Signature from Server")
            sys.exit()

        # convert the public ECDHE to bytes in PEM format
        client_pubDH = self.client_public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        # obtain the client's signature
        client_signature = sign_msg(self.private_key, client_pubDH)
        # sends the public value to the server
        socket.send(bytes(json.dumps({"client_public": client_pubDH.decode('utf-8'), "signature": base64.b64encode(client_signature).decode('utf-8')})+TERMINATOR, 'utf-8'))

        # Generating the session key
        self.client_session_key = sessionKey(self.client_private, server_public)
        log(logging.DEBUG,"Session Key SUCCESSFULLY ESTABLISHED")
       
    # function to send the client's public key to the server, 
    # which it will store in a local database
    def exchange_public_key(self):
        # Receive the server's public key
        server_rcvd = socket.recv(BUFSIZE)
        server_parsed = json.loads(server_rcvd.decode('utf-8'))
        server_public_key = server_parsed['public_key'].encode()
        server_signature = base64.b64decode(server_parsed['signature'].encode())
        
      	# Verify the server's signature
        try:
        	verify_sign(serialization.load_pem_public_key(server_public_key,default_backend()),server_signature,server_public_key)
        	log(logging.DEBUG,"Server's Public Key SUCCESSFULLY RECEIVED")
        except:
        	log(logging.ERROR, "Invalid Signature\n")
        	sys.exit()

        # Store the server's public key
        self.server_pubKey = serialization.load_pem_public_key(server_public_key,default_backend())
        
        # Convert to bytes the client's Public Key
        pem = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        # Responds with the client's public key signed by the client
        socket.send(bytes(json.dumps({"public_key": pem.decode('utf-8'), "signature": base64.b64encode(sign_msg(self.private_key, pem)).decode('utf-8')})+TERMINATOR, 'utf-8'))
        log(logging.DEBUG,"Client's Public Key SUCCESSFULLY SENT TO THE SERVER")

    def request_PubKey(self,receiver):
        tipo = "recPK"

        # Generate a random number for the CTR mode
        ctr = counterMode()
        # Cipher the message with the session key
        msg = AES_encrypt(self.client_session_key, ctr, json.dumps({"type": tipo, "receiver": receiver})+TERMINATOR)

        # Request the public key
        socket.send(base64.b64encode(msg)+"\n".encode('utf-8')+base64.b64encode(ctr))

        # Receive the public key
        server_rcvd = socket.recv(BUFSIZE)
        server_rcvd = server_rcvd.split(b"\n")
        msg = base64.b64decode(server_rcvd[0])
        ctr = base64.b64decode(server_rcvd[1])
        server_rcvd = AES_decrypt(self.client_session_key, ctr, msg)
        server_parsed = json.loads(server_rcvd.decode('utf-8'))
        
        try:
	        rec_PK = serialization.load_pem_public_key(server_parsed["publicKey"].encode('utf-8'),default_backend())
        except:
        	log(logging.ERROR, "ERROR: {}".format(server_parsed["error"]))
        	return None

        if rec_PK is None:
            log(logging.ERROR,"User's Public Key COULDN'T BE RETRIEVED")
            return None
        else:
            log(logging.DEBUG,"User's Public Key SUCCESSFULLY RECEIVED")

        return rec_PK
        

if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    client = None

    try:
        log(logging.INFO, "Starting Secure IM Client v1.0")
        socket = socket(AF_INET, SOCK_STREAM)
        addr = '127.0.0.1'
        client = Client(socket, addr)
        socket.connect((addr, PORT))
        log(logging.INFO, "Secure IM client connected on %s" %
            str(socket.getsockname()))

        # send client public key to the server, which it will store
        client.exchange_public_key()

        # establishing the session key between client and server
        client.client_session_key_establishment()

        while True:
            try:
                client.loop()
            except KeyboardInterrupt:
                client.close()
                log(logging.INFO, "CTRL-C pressed: Quitting!")
                break
    except:
        logging.exception("Client ERROR")
        if client is not (None):
            client.close()
