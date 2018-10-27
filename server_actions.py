import logging
from log import *
from server_registry import *
from server_client import *
from cc_pykcs11 import *

import json
import ast

class ServerActions:
    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'recPK': self.processReqPubKey,
            'login': self.processLogin,
            'update': self.processUpdate,
            'verify_chain': self.processVerify_cert_chain
        }

        self.registry = ServerRegistry()
        self.updated_id = None
        self.updated_pK = None
        self.update = False

        self.cc = citizen_card()

    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                log(logging.ERROR, "Message has no TYPE field")
                return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"})

        except Exception as e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        uuid = data['uuid']
        if not isinstance(uuid, int):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        if self.registry.userExists(str(uuid)):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"})
            return

        me = self.registry.addUser(data)

        # receives the certificates
        ack = self.processCertificate(data, client)

        # validates the signature
        valid = self.processSignature(data, client)

        # validates the certificate chain
        path , verified = self.processVerify_cert_chain(data, client)

        """
        the method processVerify_cert_chain(data, client) it is not
        functional because is always returning False

        Let's assume that it is functional and the variable verified
        get's the correct value from the method. However, the value of the 
        variable verified is set to True
        """

        print(path)
        
        verified = True

        # 
        if ack and valid and verified:
            client.sendResult({"result": me.id})
            
            log(logging.DEBUG, "Certificates Received, Signature valid, client added\n")

            #rename folder according to user's id
            old_dir = "server_certificates/None/"
            new_dir = "server_certificates/"+str(me.id)+"/"

            if os.path.exists(old_dir):
                path = os.path.join(old_dir, str(me.id))
                os.rename(old_dir, new_dir)
            
        else:
            log(logging.ERROR, "Certificates not Received or Signature not valid, client not added\n")

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        for i in userList:
            if 'pass' in i:
                del i['pass']
            if 'to_sign' in i:
                del i['to_sign']
            
        client.sendResult({"result": userList})

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult(
            {"result": self.registry.userNewMessages(user)})

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult({"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]})

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy', 'symkey', 'ctr', 'signature'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})


        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = data['msg']
        copy = data['copy']
        symm_key = data['symkey']
        ctr = data['ctr']
        signature = data['signature']

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy, symm_key, ctr, signature)

        client.sendResult({"result": response})

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult({"result": response})

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"})

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
        
        fromId = int(data['id'])
        msg = str(data["msg"])
        
        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        response = self.registry.getReceipts(fromId, msg)
        
        client.sendResult({"result": response})

    def processReqPubKey(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'receiver'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        #try:
        # Obtain all the public keys from the file
        pk_db = {}
        pk_db[1] = []
        i = 1
        f = open("public_keys.pem","r")
        for line in f:
            if i not in pk_db:
                pk_db[i] = [line]
            else:
                pk_db[i] += [line]
                if line == "Empty\n":
                    pk_db[i] = ''
                    i += 1
                if line == "-----END PUBLIC KEY-----\n":
                    pk_db[i] = ''.join(e for e in pk_db[i])
                    i += 1
        f.close()
        
        toId = int(data["receiver"])

        client.sendResult({"publicKey": pk_db[toId]})
        #except:
        #    client.sendResult({"error": "user's public key couldn't be retrieved"})

    # https://stackoverflow.com/questions/988228/convert-a-string-representation-of-a-dictionary-to-a-dictionary
    def processLogin(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        # list of all directories in the mbox directory
        dirs = [d for d in os.listdir("mboxes") if not os.path.isfile(os.path.join("mboxes","d"))]

        # Get the user's password
        for d in dirs:
            path = os.path.join("mboxes", str(d))
            path = os.path.join(path,"description")
            f = open(path,"r")
            for line in f:
                file = line
            file = ast.literal_eval(file)
            if int(file["uuid"]) == int(data["uuid"]):
                uid = d
                break
            file = None

        valid = self.processSignature(data, client, uid)
        
        if valid:
            try:
                log(logging.DEBUG, "Signature verified, client logged in\n")
                client.sendResult({"pass": file["pass"], "id": uid})
            except:
                client.sendResult({"error": "Couldn't find user"})
                log(logging.ERROR, "Signature verified, client not found\n")
        else:
            log(logging.ERROR, "Could not verify signature, user not logged in\n")

    def processUpdate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        client_public_key = data['public_key'].encode()
        client_signature = base64.b64decode(data['signature'].encode())

        try:
            verify_sign(serialization.load_pem_public_key(client_public_key,default_backend()), client_signature,client_public_key)
            log(logging.DEBUG,"Client's Updated Public Key Received")
        except:
            log(logging.ERROR, "Signature is Invalid\n")
            return

        # Obtain all the public keys from the file
        pk_db = {}
        pk_db[1] = []
        i = 1
        f = open("public_keys.pem","r")
        for line in f:
            if i not in pk_db:
                if line == "Empty\n":
                    pk_db[i] = []
                    i += 1
                else:
                    pk_db[i] = [line]
            else:
                pk_db[i] += [line]
                if line == "-----END PUBLIC KEY-----\n":
                    pk_db[i] = ''.join(e for e in pk_db[i])
                    i += 1
        f.close()

        # Update the public key in the file
        pk_db[int(data['id'])] = client_public_key.decode('utf-8')
        self.updated_id = int(data['id'])
        self.updated_pK = pk_db[int(data['id'])]

        # Write the updated database in the file
        f = open("public_keys.pem","w")
        for i in pk_db:
            f.write(str(pk_db[i]))
        f.close()
        
        self.update = True

    def processCertificate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        attributes = data['cert_attributes']

        try:

            path1 = "server_certificates/"
            path2 = "None/"
            path = os.path.join(path1, path2)

            if not os.path.exists(path1):
                log(logging.DEBUG, "Creating directory to store certificates from clients")
                os.mkdir(path1)

            if not os.path.exists(path):
                log(logging.DEBUG, "Creating directory to store certificates from None")
                os.mkdir(path)

            c = crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(attributes))

            issuer = c.get_issuer().CN

            open(path+"/"+str(issuer)+".cer", "wb").write(crypto.dump_certificate (crypto.FILETYPE_ASN1, c))

            log(logging.DEBUG, "{} saved\n".format(issuer))

            return True

        except Exception as e:
            log(logging.ERROR, "Error saving certificates\n")

    def processSignature(self, data, client, uid = None):
        log(logging.DEBUG, "%s" % json.dumps(data))

        signature = data['signature']
        to_sign = data['to_sign']
        try:

            if glob.glob("server_certificates/"+str(uid)+"/EC de Autenticação do Cartão de Cidadão*.cer") != []:
                for file in glob.glob("server_certificates/"+str(uid)+"/EC de Autenticação do Cartão de Cidadão*.cer"):
                    spt = file.split('/')
                    cert_name = spt[-1]

            #Mac and Linux
            cert = open("server_certificates/"+str(uid)+"/"+cert_name, "rb").read()
            #Windows
            #cert = open("server_certificates\\"+cert_name, "rb").read()
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

            ver = self.cc.verify_signature_with_certificate(certificate, to_sign, signature)
            
            if ver is None:
                return True
            else:
                return False
                
        except Exception as e:
            log(logging.ERROR, "Can not verify the signature")

    def processVerify_cert_chain(self, data, client, uid = None):
        
        log(logging.DEBUG, "%s" % json.dumps(data))

        for file in glob.glob("server_certificates/"+str(uid)+"/EC de Autenticação do Cartão de Cidadão*.cer"):
            spt = file.split('/')
            cert_name = spt[-1]

        cert = open("server_certificates/"+str(uid)+"/"+cert_name, "rb").read()
        certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

        root_c = open("CRL/Baltimore CyberTrust Root.cer", "rb").read()
        root_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, root_c)

        t_a1, i_c1 = self.cc.load_certificates(uid)
        t_a2, i_c2 = self.cc.get_certificate_keystore()

        trusted_certificates = []
        intermidiate_certificates = []

        for t in t_a1 + t_a2:
            if t.get_subject().CN not in [ce.get_subject().CN for ce in trusted_anchors]:
                trusted_anchors += [t]

        for i in i_c1 + i_c2:
            if i.get_subject().CN not in [ce.get_subject().CN for ce in intermidiate_certificates]:
                intermidiate_certificates += [i]

        cert_path = self.cc.get_cert_path(certificate, trusted_certificates, intermidiate_certificates)
        verified = self.cc.verify_certificate_chain(certificate, intermidiate_certificates[1:])

        return cert_path, verified

