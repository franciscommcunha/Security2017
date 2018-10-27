import os
import datetime
from log import *
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


class Certificates:
	
	def __init__(self):
		self.CERT_FILE = "Secure IM Server v1.0.cer"

	# Create a self-signed certificate
	def createSelfSignedCert(self, pubKey, privKey):
		# https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object
		builder = x509.CertificateBuilder()
		builder = builder.subject_name(x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, u'Secure IM Server v1.0')]))
		builder = builder.issuer_name(x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, u'Secure IM Server v1.0')]))
		builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(1,0,0))
		builder = builder.not_valid_after(datetime.datetime(2029, 2, 2))
		builder = builder.serial_number(x509.random_serial_number())
		builder = builder.public_key(pubKey)
		builder = builder.add_extension(
			x509.SubjectAlternativeName([x509.DNSName(u'Secure IM Server v1.0')]),
			critical=False)
		builder = builder.add_extension(
			x509.BasicConstraints(ca=False, path_length=None), critical=True)
		certificate = builder.sign(private_key=privKey,
			algorithm=hashes.SHA256(),
			backend=default_backend())
		open(self.CERT_FILE, "wb").write(
			certificate.public_bytes(serialization.Encoding.PEM))

	# Get the self-signed certificate
	def getCert(self):
		return open(self.CERT_FILE, "rb").read()

	# Verify a certificate and its chain
	def verify(self, certificate, chain):
		# Check if certificate is in trusted certificates list
		trusted_certs = [f for f in os.listdir("server_trusted_certs") if os.path.isfile(os.path.join("server_trusted_certs", f))]
		cert_name = certificate.to_cryptography().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value+".cer"
		if cert_name in trusted_certs:
			if certificate.to_cryptography().public_bytes(Encoding.DER) == open(os.path.join("server_trusted_certs", cert_name),"rb").read():
				log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
				return
			elif certificate.to_cryptography().public_bytes(Encoding.PEM) == open(os.path.join("server_trusted_certs", cert_name),"rb").read():
				log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
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
					log(logging.DEBUG, "Chain is valid\n")
			except Exception as e:
				raise Exception(e)
		
		# Update trusted certificates list
		trusted_certs = [f for f in os.listdir("server_trusted_certs") if os.path.isfile(os.path.join("server_trusted_certs", f))]

		# Check if certificate's issuer is in trusted certificates list
		store = crypto.X509Store()
		iss = certificate.to_cryptography().issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
		while True:
			try:
				ci = crypto.load_certificate(crypto.FILETYPE_ASN1, open(os.path.join("server_trusted_certs", iss+".cer"),"rb").read())
			except:
				ci = crypto.load_certificate(crypto.FILETYPE_PEM, open(os.path.join("server_trusted_certs", iss+".cer"),"rb").read())
			iss = ci.to_cryptography().issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			sub = ci.to_cryptography().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			if sub+".cer" in trusted_certs:
				if ci.to_cryptography().public_bytes(Encoding.DER) == open(os.path.join("server_trusted_certs", sub+".cer"),"rb").read():
					store.add_cert(ci)
				elif ci.to_cryptography().public_bytes(Encoding.PEM) == open(os.path.join("server_trusted_certs", sub+".cer"),"rb").read():
					store.add_cert(ci)
			if iss == sub:
				break

		# Verifiy the certificate
		store_cert = crypto.X509StoreContext(store, certificate)
		try:
			store_cert.verify_certificate()
			with open(os.path.join("server_trusted_certs", cert_name),"wb") as f:
				f.write(certificate.to_cryptography().public_bytes(Encoding.DER))
			log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
		except Exception as e:
			raise Exception(e)