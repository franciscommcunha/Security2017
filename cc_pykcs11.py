import os
from PyKCS11 import *
import binascii
import getpass
import OpenSSL
from OpenSSL import crypto
from log import *
import logging
import glob
import jks
import platform
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

################ Documentation #############
#	https://pyopenssl.readthedocs.io/en/latest/api/crypto.html#signing-and-verifying-signatures
# 	https://pkcs11wrap.sourceforge.io/api/PyKCS11.Session-class.html
################ Documentation #############


# https://ludovicrousseau.blogspot.pt/2011/04/pykcs11-provided-samples-dumpitpy.html
# https://pkcs11wrap.sourceforge.io/api/PyKCS11.Session-class.html

class citizen_card:
	PKCS11_LIB_LINUX = "/usr/local/lib/libpteidpkcs11.so"
	PKCS11_LIB_MAC =  "/usr/local/lib/libpteidpkcs11.dylib"	
	PKCS11_LIB_WINDOWS = "c:\\Windows\\System32\\pteidpkcs11.dll"
	PKCS11_LIB = ""
	PKCS11_session = None
	CERTIFICATE_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

	KS = jks.KeyStore.load("CRL/CC_KS", "password")
	
	def __init__(self):

		# detects the operating system
		if platform.uname()[0] == "Darwin": # MAC
			if os.path.isfile(self.PKCS11_LIB_MAC):
				self.PKCS11_LIB = self.PKCS11_LIB_MAC
			else:
				print("PKCS11 library doesn't exist on OSX!")

		elif platform.uname()[0] == "Windows":
			if os.path.isfile(self.PKCS11_LIB_WINDOWS):
				self.PKCS11_LIB = self.PKCS11_LIB_WINDOWS
			else:
				print("PKCS11 library doesn't exist on Windows!")

		else:
			if os.path.isfile(self.PKCS11_LIB_LINUX):
				self.PKCS11_LIB = self.PKCS11_LIB_LINUX
			else:
				print("PKCS11 library doesn't exist on Linux!")

		self.PKCS11_session = self.get_session()
		
	def get_session(self):
		
		pkcs11 = PyKCS11.PyKCS11Lib()

		if self.PKCS11_session is None:
			try:
				pkcs11.load(self.PKCS11_LIB)
				slot = pkcs11.getSlotList(tokenPresent=True)

			except PyKCS11.PyKCS11Error:
				print("Couldn't load lib and get slot list")
				raise

			try:
				self.PKCS11_session = pkcs11.openSession(slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
				return self.PKCS11_session
			except (IndexError, PyKCS11.PyKCS11Error):
				print("Card reader not detected")
				raise

	# checks if the citizen card is detected # works
	def citizen_card_detected(self):
		
		session = self.PKCS11_session

		if session is None:
			return False
		
		return True

	# signs a message
	def sign(self, data):
		
		session = self.PKCS11_session

		if session is not None:

			try:
				label = "CITIZEN AUTHENTICATION KEY"

				private_key = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, label)])[0]
				mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
				signature = session.sign(private_key, data, mechanism)

				return base64.b64encode(bytes(signature))
				
			except PyKCS11.PyKCS11Error:
				print("Could not sign the message")

			except IndexError:
				print("CITIZEN AUTHENTICATION PRIVATE KEY not found")
				raise

	# verifies the signature of a message with the certificate of the public key
	def verify_signature_with_certificate(self, certificate, data, signature):
		# if correct returns None, else raises internal exception
		
		try:
			log(logging.DEBUG, "Verifying signature")
			
			signature = base64.b64decode(signature)
			return crypto.verify(certificate, bytes(signature), data, "SHA256") 
		
		except Exception as e:
			log(logging.ERROR, "Error verifying signature")
			print(e)
			raise
		
	# checks the signature of a message
	def verify_signature(self, data, signature):

		session = self.PKCS11_session
		
		if session is not None:

			try:
				signature = base64.b64decode(signature)

				public_key = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]

				mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)

				verify = session.verify(public_key, data, signature, mechanism)

				return verify

			except PyKCS11.PyKCS11Error:
				print("Could not verify the signature of the message")

			except IndexError:
				print("CITIZEN AUTHENTICATION PUBLIC KEY not found")
				raise
		
	# saves the certificates from the citizen card in DER Format 
	def save_certificates(self, id):
		
		# https://stackoverflow.com/questions/39346577/pykcs11-get-token-certificates

		session = self.PKCS11_session

		path = "client_certificates" # nome da pasta onde vao ser guardados os certificados

		if not os.path.exists(path):
			logging.debug("\nCreating directory to store saved certificates")
			os.mkdir(path)
		
		path = os.path.join(path, str(id))

		if not os.path.exists(path):
			logging.debug("\nCreating directory to store saved certificates for user {}".format(id))
			os.mkdir(path)
		
		if session is not None:
			
			certificates = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

			for cert in certificates:
				#print(cert.to_dict()['CKA_LABEL'])

				try:
					attributes = session.getAttributeValue(cert, [CKA_VALUE])
				except PyKCS11.PyKCS11Error as e:
					continue

				c = crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(attributes[0]))
				
				# Convert to PEM format
				#c = crypto.dump_certificate(crypto.FILETYPE_PEM, str(attributes[0]))
				
				subject = c.get_subject().CN
				issuer = c.get_issuer().CN

				# save the certificates
				open(path+"/"+str(issuer)+".cer", "wb").write(crypto.dump_certificate (crypto.FILETYPE_ASN1, c))

	def get_cert_attributes(self):

		session = self.PKCS11_session

		if session is not None:
			certificates = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

			for cert in certificates:
				#print(cert)
				#print(cert.to_dict()['CKA_LABEL'])

				try:
					attributes = session.getAttributeValue(cert, [CKA_VALUE])
					return attributes
				except PyKCS11.PyKCS11Error as e:
					continue

	# loads the certificates and returns trusted anchors and intermidiate certificates
	def load_certificates(self, uid):
		trusted_anchors = [] # list of trusted anchors
		intermediate_certificates = [] # list of intermediate certificates

		path = "server_certificates/"+str(uid)+"/"
		#path = "client_certificates/3/" # for testing

		# gets the total path to the directory
		current_directory = os.getcwd()
		j = os.path.join(current_directory, path)
		directory = os.listdir(j)

		for cert in directory:
			cert_path = os.path.join(os.path.join(os.getcwd(), path), cert)
			open_cert = open(cert_path, "rb").read()

			c = crypto.load_certificate(crypto.FILETYPE_ASN1, open_cert)

			subject = c.get_subject().CN
			issuer = c.get_issuer().CN

			# self-certified certtificates can be easily detected because their signature can be validated with their own public key
			if subject == issuer:
				trusted_anchors += [c]
			else:
				intermediate_certificates += [c] 

		return trusted_anchors, intermediate_certificates

	def get_certificate_PEM(self):

		session = self.PKCS11_session

		label = "CITIZEN AUTHENTICATION CERTIFICATE"

		if session is not None:
			try:
				certificate = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
			except PyKCS11.PyKCS11Error as e:
				print("Couldn't get certificate from smart card")
				raise

			try:
				der = ''.join(chr(c) for c in certificate[0].to_dict()['CKA_VALUE'])
			except (IndexError, TypeError):
				print("CITIZEN AUTHENTICATION CERTIFICATE not found.")
				raise

			return x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)
			
	# reads the certificate and returns the public key in pem and der format
	def get_pub_key_certificate(self, certificate):
		
		try:
			pub = certificate.get_pubkey()

			# DER FORMAT
			pub_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, pub)

			# PEM FORMAT
			pub_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, pub)
			return pub_key_der, pub_key_pem

		except Exception as e:
			print(e)
			return False

	# gets the digest 
	def get_digest_pub_key(self, certificate):
		
		try:
			subject = certificate.subject_name_hash()
			return subject
		except Exception as e:
			print(e)
			return False

	# ver melhor
	def verify_certificate_chain(self, certificate, trusted_certificates):

		# http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/

		# trusted certs é a entidade raiz, tipo o Baltimore

		try:
			store = crypto.X509Store()

			# Adds a trusted certificate to this store
			for cert in trusted_certificates:
				store.add_cert(cert)

			# An X.509 store context is used to carry out the actual verification process of a certificate in a described context.
			store_context = crypto.X509StoreContext(store, certificate)

			# verifies the certificate
			store_context.verify_certificate()

			return True

		except Exception as e:
			print(e)
			return False

	# gets the certification path of a certificate and returns that path
	def get_cert_path(self, certificate, trusted_anchors, intermediate_certificates, cert_path = {}):
		# HELP with Diogo Daniel Soares Ferreira
		
		issuer = certificate.get_issuer().CN
		subject = certificate.get_subject().CN

		# Check if it has expired
		if(certificate.has_expired()):
			return None

		if cert_path == {}:
			cert_path[subject] = issuer

		for c in intermediate_certificates:
			# Check if the issuer of the certificate is the subject of the parent
			parent_issuer = c.get_issuer().CN
			parent_subject = c.get_subject().CN

			if(subject != parent_subject and issuer == parent_subject):
				cert_path[issuer] = parent_issuer
				cert_path = self.get_cert_path(c, trusted_anchors, intermediate_certificates, cert_path)
				return cert_path

		# no trusted anchors with the old middleware
		for trusted in trusted_anchors:
			parent_issuer = trusted.get_issuer().CN
			parent_subject = trusted.get_subject().CN

			if(subject == parent_subject):
				return cert_path

		# With the old middleware we need this return...
		return cert_path

	# https://github.com/kurtbrose/pyjks
	def get_certificate_keystore(self):
		
		trusted_certificates = []
		intermidiate_certificates = []
		for alias, c in self.KS.certs.items():
			
			load_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, c.cert)

			issuer = load_cert.get_issuer().CN
			subject = load_cert.get_subject().CN
			
			if subject == issuer:
				trusted_certificates += [load_cert]
			else:
				intermidiate_certificates += [load_cert]

			ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
			cert_store = ctx.get_cert_store()

			for cert in intermidiate_certificates:
				cert_store.add_cert(cert)
				
		return trusted_certificates, intermidiate_certificates
"""
if __name__ == "__main__":

	cc = citizen_card()
	
	for file in glob.glob('client_certificates/3/EC de Autenticação do Cartão de Cidadão*.cer'):
		spt = file.split('/')
		cert_name = spt[-1]
	
	cert = open("client_certificates/3/"+cert_name, "rb").read()
	certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert) # OpenSSL.crypto.X509 object at 0x105dbf74
 	
	root_c = open("client_certificates/3/Baltimore CyberTrust Root.cer", "rb").read()
	root_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, root_c)

	t_a1, i_c1 = cc.load_certificates(3)
	t_a2, i_c2 = cc.get_certificate_keystore()

	trusted_certificates = []
	intermidiate_certificates = []

	for t in t_a1 + t_a2:
		if t.get_subject().CN not in [ce.get_subject().CN for ce in trusted_anchors]:
			trusted_anchors += [t]

	for i in i_c1 + i_c2:
		if i.get_subject().CN not in [ce.get_subject().CN for ce in intermidiate_certificates]:
			intermidiate_certificates += [i]

	print(cc.get_cert_path(certificate, trusted_certificates, intermidiate_certificates))
	print(cc.verify_certificate_chain(intermidiate_certificates[0], intermidiate_certificates[1:]))
	
	#for file in glob.glob('client_certificates/3/EC de Autenticação do Cartão de Cidadão*.cer'):
	#	spt = file.split('/')
	#	cert_name = spt[-1]
	
	#cert = open("client_certificates/3/"+cert_name, "rb").read()
	#certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert) # OpenSSL.crypto.X509 object at 0x105dbf74

	#ctx = cc.get_certificate_keystore()

	#trusted_certificates = []
	#intermidiate_certificates = []

	#trusted_certificates, intermidiate_certificates = cc.load_certificates()
	#print(cc.verify_certificate_chain(certificate, intermidiate_certificates))
"""
