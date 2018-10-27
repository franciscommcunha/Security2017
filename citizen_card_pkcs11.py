# http://python-pkcs11.readthedocs.io/en/latest/applied.html#importing-exporting-keys

# http://python-pkcs11.readthedocs.io/en/latest/api.html
# https://pypi.python.org/pypi/pyjks

import os
import pkcs11
from pkcs11 import *
import getpass
import OpenSSL
from OpenSSL import crypto
from log import *
import logging
#import jks
import platform

from pkcs11.util.x509 import decode_x509_certificate
from pkcs11.util import rsa
from pkcs11.util import dsa


class citizen_card:
	PKCS11_LIB_LINUX = "/usr/local/lib/libpteidpkcs11.so"
	PKCS11_LIB_MAC =  "/usr/local/lib/libpteidpkcs11.dylib"	
	PKCS11_LIB_WINDOWS = "c:\\Windows\\System32\\pteidpkcs11.dll"
	PKCS11_LIB = ""
	
	def __init__(self):

		# detects the operating system
		if os.uname()[0] == "Darwin": # MAC
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
		
		self.lib = pkcs11.lib(self.PKCS11_LIB) # lib to use
		self.token = None

		# select the desired token
		tokens = self.lib.get_tokens()

		for t in tokens:
			self.token = t
			break

	# gets the authentication public key and save on a file
	def save_auth_pub_key(self):

		with self.token.open() as session:

			objs = session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY})
	
			pubKey = None

			for obj in objs:
				if "AUTH" in str(obj).upper():
					pubKey = obj
					break
				
			objs = None

			if pubKey is None:
				print("No pubKey")

			# To export an RSA public key in PKCS #1 DER-encoded format
			public_key = pkcs11.util.rsa.encode_rsa_public_key(pubKey)

			# writes the pub_key to a file
			pub = open("auth_publicKey_cc.txt", 'wb')
			pub.write(public_key)
			pub.close()

			return pubKey
			
	# loads the authentication public key from the file
	def load_auth_pub_key(self):
		
		pub = open("auth_publicKey_cc.txt", 'rb')
		public = pub.read()
		pub.close()

		public_key = pkcs11.util.rsa.decode_rsa_public_key(public)
		
		return public_key

	# signs a data string with the authentication private key
	def sign_auth_private_key(self, data):
		
		with self.token.open() as session:

			objs = session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY})
			private = None	

			for obj in objs:
				if("AUTH" in str(obj).upper()):
					private = obj
					break

			objs = None

			if(private is None):
				print("No private Authentication Key Found.")

			# http://python-pkcs11.readthedocs.io/en/latest/api.html#object-capabilities
			signature = private.sign(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)
			return signature
			
	# verifies if the signature is correct
	def verify_auth_signature(self, data, signature):

		with self.token.open() as session:

			objs = session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY})
			pub_key = None	

			for obj in objs:
				if("AUTH" in str(obj).upper()):
					pub_key = obj
					break

			objs = None

			if(pub_key is None):
				print("No public Authentication Key Found.")


			# <class '__main__.PublicKey'>
			return pub_key.verify(data, signature, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

	# saves the certificates from the cc in DER format
	def save_certificates(self):

		# http://python-pkcs11.readthedocs.io/en/latest/applied.html#exporting-certificates

		path = "certificates"
		
		with self.token.open() as session:

			objs = session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})

			for cert in objs:

				# Convert from DER-encoded value to OpenSSL object
				c = crypto.load_certificate(crypto.FILETYPE_ASN1, cert[Attribute.VALUE])

				subject = c.get_subject().CN
				issuer = c.get_issuer().CN

				# Convert to PEM format
   	 			#c = crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

				# save the certificates
				open(path+"/"+str(subject)+"_"+str(issuer)+".cer", "wb").write(crypto.dump_certificate (crypto.FILETYPE_ASN1, c))
				
	# loads the saved cc certificates in DER format
	def load_certificates(self):
		
		path = "certificates"

		t_a = [] # trusted anchors
		i_c = [] # intermidiate certificates

		# gets the total path to the directory
		current_directory = os.getcwd()
		j = os.path.join(current_directory, path)
		directory = os.listdir(j)

		os.remove("certificates/.DS_Store")

		for cert in directory:
			cert_path = os.path.join(os.path.join(os.getcwd(), path), cert)
			open_cert = open(cert_path, "rb").read()

			c = crypto.load_certificate(crypto.FILETYPE_ASN1, open_cert)

			subject = c.get_subject().CN
			issuer = c.get_issuer().CN

			if subject == issuer:
				t_a += [c]
			else:
				i_c += [c]

		return t_a, i_c

	def get_cert_keystore(self):
		t_a = [] # trusted anchors
		i_c = [] # intermidiate certificates

		keystore = jks.KeyStore.load('KeyStore/CC_KS', 'password')

		for alias, certificate in keystore.certs.items():

			c = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate.cert)

			subject = c.get_subject().CN
			issuer = c.get_issuer().CN

			if(subject==issuer):
				t_a += [c]
			else:
				i_c += [c]

		return t_a, i_c

	# http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/
	def verify_certificate_chain(self, certificate, trusted_certificates):
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

	def get_cert_keystore(self):
		trusted_anchors = []
		intermediate_certificates = []

		keystore = jks.KeyStore.load('Keystore/CC_KS', 'password')

		for alias, certificate in keystore.certs.items():

			t = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate.cert)

			subject = t.get_subject().CN
			issuer = t.get_issuer().CN

			if(subject==issuer):
				trusted_anchors += [t]
			else:
				intermediate_certificates += [t]

		return trusted_anchors, intermediate_certificates

	def get_cert_path(self, certificate, trusted_anchors, intermediate_certificates, path = {}):
		
		issuer = certificate.get_issuer().CN
		subject = certificate.get_subject().CN

		# Check if it has expired
		if(certificate.has_expired()):
			return None

		if path == {}:
			path[subject] = issuer

		for c in intermediate_certificates:
			# Check if the issuer of the certificate is the subject of the parent
			parent_issuer = c.get_issuer().CN
			parent_subject = c.get_subject().CN
			if(subject != parent_subject and issuer == parent_subject):

				# print(certificate.verify(c.get_pubkey()))
				path[issuer] = parent_issuer
				path = self.get_cert_path(c, trusted_anchors, intermediate_certificates, path)
				return path

		# With the old middleware there are no trusted anchors...
		for trusted in trusted_anchors:
			parent_issuer = trusted.get_issuer().CN
			parent_subject = trusted.get_subject().CN

			if(subject == parent_subject):
				return path

		# With the old middleware we need this return...
		return path


if __name__ == "__main__":

	cc = citizen_card()

	#pub_save = cc.save_auth_pub_key()
	#pub_load = cc.load_auth_pub_key()

	data = "Francisco Cunha"
	signature_auth = cc.sign_auth_private_key(data)
	print(cc.verify_auth_signature(data, signature_auth))

	#cc.save_certificates()
	
	"""
	t_a1, i_c1 = cc.load_certificates()
	t_a2, i_c2 = cc.get_cert_keystore()

	intermediate_certificates = []
	trusted_anchors = []

	for t in t_a1+t_a2:
		if t.get_subject().CN not in [ce.get_subject().CN for ce in trusted_anchors]:
			trusted_anchors += [t]

	for i in i_c1+i_c2:
		if i.get_subject().CN not in [ce.get_subject().CN for ce in intermediate_certificates]:
			intermediate_certificates += [i]

	print(cc.get_cert_path(intermediate_certificates[0], trusted_anchors, intermediate_certificates))
	print("\n")
	print(cc.verify_certificate_chain(intermediate_certificates[0], intermediate_certificates[1:]))
	"""
	
	#cert = open("certificates/ECRaizEstado.crt", "rb").read()
	#print(cc.verify_certificate_chain("cert"))


