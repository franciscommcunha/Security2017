import os, platform
import logging
import OpenSSL
from log import *
from PyKCS11 import *
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class CitizenCard:
	# Class variables
	PKCS11_LIB_LINUX = "/usr/local/lib/libpteidpkcs11.so"
	PKCS11_LIB_MAC =  "/usr/local/lib/libpteidpkcs11.dylib"	
	PKCS11_LIB_WINDOWS = "c:\\Windows\\System32\\pteidpkcs11.dll"
	PKCS11_LIB = ""
	PKCS11_session = None
	CERTIFICATE_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

	def __init__(self):
		# Detects the operating system
		if platform.uname()[0] == "Darwin": # MAC
			if os.path.isfile(self.PKCS11_LIB_MAC):
				self.PKCS11_LIB = self.PKCS11_LIB_MAC
			else:
				log(logging.ERROR,"PKCS11 library doesn't exist on OSX!\n")

		elif platform.uname()[0] == "Windows":
			if os.path.isfile(self.PKCS11_LIB_WINDOWS):
				self.PKCS11_LIB = self.PKCS11_LIB_WINDOWS
			else:
				log(logging.ERROR,"PKCS11 library doesn't exist on Windows!\n")

		else:
			if os.path.isfile(self.PKCS11_LIB_LINUX):
				self.PKCS11_LIB = self.PKCS11_LIB_LINUX
			else:
				log(logging.ERROR,"PKCS11 library doesn't exist on Linux!\n")

		try:
			self.PKCS11_session = self.get_session()
		except Exception as e:
			log(logging.ERROR, e)

	# Gets the pkcs11 session, if there is None, one is created
	def get_session(self):
		pkcs11 = PyKCS11.PyKCS11Lib()

		if self.PKCS11_session is None:
			try:
				pkcs11.load(self.PKCS11_LIB)
				slot = pkcs11.getSlotList(tokenPresent=True)
			except PyKCS11.PyKCS11Error:
				raise Exception("Couldn't load lib and get slot list\n")

			try:
				self.PKCS11_session = pkcs11.openSession(slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
				return self.PKCS11_session
			except (IndexError, PyKCS11.PyKCS11Error):
				raise Exception("Card reader not detected\n")
		else:
			return self.PKCS11_session

	# Checks if the citizen card is detected
	def citizen_card_detected(self):
		return False if self.PKCS11_session is None else True
	
	# Digest the user's certificate public key
	def get_digest(self, certificate):
		try:
			pK = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
			digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
			digest.update(pK)
			return digest.finalize()
		except Exception as e:
			log(logging.ERROR, e)
			return None

	# Extract the certificate from the Citizen Card
	def extract_certificates(self, id):
		session = self.PKCS11_session

		# Name of the directory where the certificates will be stored
		path = "client_certificates"
		# Create the directory
		if not os.path.exists(path):
			#log(logging.DEBUG, "Creating directory to store certificates\n")
			os.mkdir(path)

		# Name of the directory where the certificate is stored
		path = os.path.join(path, str(id))
		# Create the directory
		if not os.path.exists(path):
			#log(logging.DEBUG, "Creating directory to store user's certificates\n")
			os.mkdir(path)

		if session is not None:
			# Find all the certificates
			objects = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

			for obj in objects:
				# Obtain attributes from certificate
				try:
					attributes = session.getAttributeValue(obj, [PyKCS11.CKA_VALUE])[0]
				except PyKCS11.PyKCS11Error as e:
					continue

				# Load certificate from DER format
				cert = x509.load_der_x509_certificate(bytes(attributes), default_backend())
				# Obtain certificate's subject
				subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
				# Obtain certificate's issuer
				issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

				try:
					# 
					if "EC de Autenticação do Cartão de Cidadão"in subject or "EC de Autenticação do Cartão de Cidadão" in issuer:
						# Create the directory
						if not os.path.exists(os.path.join(path,"ECs de Autenticação")):
							os.mkdir(os.path.join(path,"ECs de Autenticação"))
						# Save certificate in directory
						#open(path+"/ECs de Autenticação/*"+str(subject)+".cer", "wb").write(cert.public_bytes(Encoding.PEM))
						# Windows Version
						open(path+"\\ECs de Autenticação\\"+str(subject)+".cer", "wb").write(cert.public_bytes(Encoding.PEM))
					#
					elif "EC de Assinatura Digital Qualificada do Cartão de Cidadão" in subject or "EC de Assinatura Digital Qualificada do Cartão de Cidadão" in issuer:
						# Create the directory
						if not os.path.exists(os.path.join(path,"ECs de Assinatura Digital")):
							os.mkdir(os.path.join(path,"ECs de Assinatura Digital"))
						# Save certificate in directory
						#open(path+"/ECs de Assinatura Digital/"+str(subject)+".cer","wb").write(cert.public_bytes(Encoding.PEM))
						# Windows version
						open(path+"\\ECs de Assinatura Digital\\"+str(subject)+".cer","wb").write(cert.public_bytes(Encoding.PEM))
					else:
						# Save certificate in directory
						open(path+"/"+str(subject)+".cer", "wb").write(
							cert.public_bytes(Encoding.PEM))
				except Exception as e:
					log(logging.ERROR, e)

	# Get a certificate's public key
	def get_PublicKey(self, certificate):
		return certificate.public_key()

	# Sign a message with the private citizen authentication key
	def sign(self, msg):
		if self.PKCS11_session is not None:
			try:
				label = "CITIZEN AUTHENTICATION KEY"
				privK = self.PKCS11_session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, label)])[0]
				mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
				return bytes(self.PKCS11_session.sign(privK, msg, mechanism))
			except PyKCS11.PyKCS11Error:
				log(logging.ERROR, "Could not sign the message\n")
			except IndexError:
				log(logging.ERROR,"CITIZEN AUTHENTICATION PRIVATE KEY not found\n")

	# Get certificates to sign a message and exctract user's name
	def getCert(self, uuid):
		#onlyfiles = [f for f in os.listdir("client_certificates/"+str(uuid)+"/ECs de Autenticação") if os.path.isfile(os.path.join("client_certificates/"+str(uuid)+"/ECs de Autenticação", f))]
        # Windows Version
		onlyfiles = [f for f in os.listdir("client_certificates\\"+str(uuid)+"\\ECs de Autenticação") if os.path.isfile(os.path.join("client_certificates\\"+str(uuid)+"\\ECs de Autenticação", f))]
		for f in onlyfiles:
			if "EC de Autenticação do Cartão de Cidadão" not in f:
				name = f
			else:
				c_sign = f
		#cert_name = open("client_certificates/"+str(uuid)+"/ECs de Autenticação/"+name, "rb").read()
		# Windows Version
		cert_name = open("client_certificates\\"+str(uuid)+"\\ECs de Autenticação\\"+name, "rb").read()
		#cert_sign = open("client_certificates/"+str(uuid)+"/ECs de Autenticação/"+c_sign, "rb").read()
		# Windows Version
		cert_sign = open("client_certificates\\"+str(uuid)+"\\ECs de Autenticação\\"+c_sign, "rb").read()
		return cert_name, cert_sign

	# Get the chain of a given certificate
	def getChain(self, uuid, cert):
		chain = []
		path = os.path.join("client_certificates", str(uuid))
		i = self.getIssuer(cert)
		trusted_certs = [f for f in os.listdir("client_trusted_certs") if os.path.isfile(os.path.join("client_trusted_certs", f))]
		while True:
			try:
				chain += [open(os.path.join(path, i+".cer"), "rb").read()]
			except FileNotFoundError:
				chain += [open(os.path.join(os.path.join(path, "ECs de Autenticação"), i+".cer"), "rb").read()]
			cert = chain[-1]
			i = self.getIssuer(cert)
			if i+".cer" in trusted_certs:
				break
		return chain

	# Get the issuer of a given certificate
	def getIssuer(self, cert):
		certificate = x509.load_pem_x509_certificate(cert, default_backend())
		issuer = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
		return issuer

	# Verify a certificate and its chain
	def verify(self, certificate, chain):
		# Check if certificate is in trusted certificates list
		trusted_certs = [f for f in os.listdir("client_trusted_certs") if os.path.isfile(os.path.join("client_trusted_certs", f))]
		cert_name = certificate.to_cryptography().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value+".cer"
		if cert_name in trusted_certs:
			if certificate.to_cryptography().public_bytes(Encoding.DER) == open(os.path.join("client_trusted_certs", cert_name),"rb").read():
				#log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
				return
			elif certificate.to_cryptography().public_bytes(Encoding.PEM) == open(os.path.join("client_trusted_certs", cert_name),"rb").read():
				#log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
				return

		# Convert the certificates into a crypto.x509 object
		tmp = []
		for i in chain:
			tmp.append(crypto.load_certificate(crypto.FILETYPE_PEM, i))
			
		# Check if any certificate has expired
		if certificate.has_expired():
			raise Exception
		for i in tmp:
			if i.has_expired():
				raise Exception
		
		# Verify the chain
		if len(chain) != 0:
			try:
				ch = []
				for i in range(len(tmp)-1,-1,-1):
					self.verify(tmp[i], ch)
					ch += [chain[i]]
					#log(logging.DEBUG, "Chain is valid\n")
			except Exception as e:
				raise Exception(e)
		
		# Update trusted certificates list
		trusted_certs = [f for f in os.listdir("client_trusted_certs") if os.path.isfile(os.path.join("client_trusted_certs", f))]

		# Check if certificate's issuer is in trusted certificates list
		store = crypto.X509Store()
		iss = certificate.to_cryptography().issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
		while True:
			try:
				ci = crypto.load_certificate(crypto.FILETYPE_ASN1, open(os.path.join("client_trusted_certs", iss+".cer"),"rb").read())
			except:
				ci = crypto.load_certificate(crypto.FILETYPE_PEM, open(os.path.join("client_trusted_certs", iss+".cer"),"rb").read())
			iss = ci.to_cryptography().issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			sub = ci.to_cryptography().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			if sub+".cer" in trusted_certs:
				if ci.to_cryptography().public_bytes(Encoding.DER) == open(os.path.join("client_trusted_certs", sub+".cer"),"rb").read():
					store.add_cert(ci)
				elif ci.to_cryptography().public_bytes(Encoding.PEM) == open(os.path.join("client_trusted_certs", sub+".cer"),"rb").read():
					store.add_cert(ci)
			if iss == sub:
				break

		# Verifiy the certificate
		store_cert = crypto.X509StoreContext(store, certificate)
		try:
			store_cert.verify_certificate()
			with open(os.path.join("client_trusted_certs", cert_name),"wb") as f:
				f.write(certificate.to_cryptography().public_bytes(Encoding.DER))
			#log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
		except Exception as e:
			raise Exception(e)