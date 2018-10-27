import random
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa,padding,ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# function to generate the ECDHE (Eliptic-Curve Diffie-Hellman Ephemeral)
# private key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.ECDH
def privateKeyECDHE():
	return ec.generate_private_key(ec.SECP256R1(), default_backend())

# function to generate the ECDHE (Eliptic-Curve Diffie-Hellman Ephemeral)
# public key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.ECDH
def publicKeyECDHE(ecdhe):
	return ecdhe.public_key()

# function to generate the session key using 
# ECDHE (Eliptic-Curve Diffie-Hellman Ephemeral)
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.ECDH
def sessionKey(privKeyDH,pubKeyDH):
	return privKeyDH.exchange(ec.ECDH(), pubKeyDH)

# function to generate the secret 256-bit (32 byte) shared/symmetric key
# https://docs.python.org/3/library/os.html
def generate_symm():
	return os.urandom(32)

# function to generate a random 128-bit (16 byte) number for use in
# COUNTER mode
# https://docs.python.org/3/library/os.html
def counterMode():
	return os.urandom(16)

# function to encrypt messages using AES 256-bit algorithm
# size of AES block = 16 bytes (128-bit)
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
def AES_encrypt(key,ctr,msg):
	cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend = default_backend())
	encryptor = cipher.encryptor()
	return encryptor.update(bytes(msg,'utf-8')) + encryptor.finalize()

# function to decipher the messages using AES 256-bit algorithm
# size of AES block = 16 bytes (128-bit)
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
def AES_decrypt(key,ctr,msg):
	cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend = default_backend())
	decryptor = cipher.decryptor()
	return decryptor.update(msg) + decryptor.finalize()

# function to generate a 2048 bits RSA private key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def getPrivRSA():
	return rsa.generate_private_key(65537,2048,backend = default_backend())

# function to generate a 2048 bits RSA public key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def getPubRSA(privKey):
	return privKey.public_key()

# function to create a signature using RSA algorithm
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def sign_msg(privKey,data):
	return privKey.sign(
		data,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
		hashes.SHA256())

# function to verify the sender's signature
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def verify_sign(public_key, signature, msg):
	return public_key.verify(
		signature,
		msg,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
		hashes.SHA256())