from log import *
from server_registry import *
from server_client import *
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from certificates import *
import datetime
import json
import logging
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
        }

        self.registry = ServerRegistry()
        self.certs = Certificates()

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

        if not set(data.keys()).issuperset(set({'uuid', 'name', 'pubKey', 'signature', 'certificate', 'chain'})):
            log(logging.ERROR,
                "Badly formated \"create\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        uuid = data['uuid']
        name = data['name']
        pubKey = data['pubKey']
        signature = base64.b64decode(data['signature'])
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, data['certificate'].encode())
        chain = data['chain']
        
        # verify the certificate
        try:
            self.certs.verify(certificate, chain)
            log(logging.DEBUG, "Certificate is valid\n")
        except:
            log(logging.ERROR, "Certificate is Invalid\n")
            client.sendResult({"error": "Certificate is Invalid"})
            return
        # verify the signature
        try:
            crypto.verify(certificate,signature,str(uuid)+name+str(pubKey.encode()),"SHA256")
            log(logging.DEBUG, "Signature is Valid\n")
        except Exception as e:
            log(logging.ERROR, "Signature is Invalid\n")
            client.sendResult({"error": e})
            return

        if not isinstance(uuid, int):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return
        
        if self.registry.userExists(str(uuid)):
            me = self.registry.getUser(str(uuid))
            with open("public_keys.pem", "w") as f:
                f.write(str({me: pubKey})+"\n")
            client.sendResult({"result": me})
        else:
            me = self.registry.addUser(data)
            with open("public_keys.pem", "w") as f:
                f.write(str({me.id: pubKey})+"\n")
            client.sendResult({"result": me.id})

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"list\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)
    
        client.sendResult({"result": userList})

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"new\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

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

        if not set({'id'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"all\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

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

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'symkey', 'ctr', 'signature', 'certificate', 'chain', 'copy'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = data['msg']
        symm_key = data['symkey']
        ctr = data['ctr']
        signature = data['signature']
        certificate = data['certificate']
        chain = data['chain']
        copy = data['copy']

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
        response = self.registry.sendMessage(srcId, dstId, msg, symm_key, ctr, signature, certificate, chain, copy)

        client.sendResult({"result": response})

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

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

        if not set({'id', 'msg', 'receipt', 'certificate', 'chain'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"})
            return

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])
        certificate = str(data['certificate'])
        chain = data['chain']

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        self.registry.storeReceipt(fromId, msg, receipt, certificate, chain)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

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

        if not set({'dst'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recPK\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        try:
            # Obtain all the public keys from the file
            # https://stackoverflow.com/questions/988228/convert-a-string-representation-of-a-dictionary-to-a-dictionary
            pk_db = {}
            with open("public_keys.pem","r") as f:
                for line in f:
                    l = ast.literal_eval(line)
                    pk_db.update(l)
        except Exception as e:
            client.sendResult({"error": e})
            return
        
        toId = int(data["dst"])
        try:
            client.sendResult({"publicKey": pk_db[toId]})
        except Exception as e:
            log(logging.ERROR, e)
            client.sendResult({"error": str(e)})
            return
