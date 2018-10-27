if __name__ == "__main__":

	cc = citizen_card()
	
	for file in glob.glob('client_certificates/3/EC de Autenticação do Cartão de Cidadão*.cer'):
		spt = file.split('/')
		cert_name = spt[-1]
	
	cert = open("client_certificates/3/"+cert_name, "rb").read()
	certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert) # OpenSSL.crypto.X509 object at 0x105dbf74
 	
	root_c = open("client_certificates/3/Baltimore CyberTrust Root.cer", "rb").read()
	root_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, root_c)

	t_a1, i_c1 = cc.load_certificates()
	t_a2, i_c2, ct = cc.get_certificate_keystore()
	ctx = [ct]

	trusted_certificates = []
	intermidiate_certificates = []

	for t in t_a1 + t_a2:
		if t.get_subject().CN not in [ce.get_subject().CN for ce in trusted_anchors]:
			trusted_anchors += [t]

	for i in i_c1 + i_c2:
		if i.get_subject().CN not in [ce.get_subject().CN for ce in intermidiate_certificates]:
			intermidiate_certificates += [i]

	#print(cc.get_cert_path(intermidiate_certificates[0], trusted_certificates, intermidiate_certificates))
	print(cc.get_cert_path(certificate, trusted, intermidiate_certificates))
	print(cc.verify_certificate_chain(certificate, intermidiate_certificates[1:]))
	
	
	"""
	for file in glob.glob('client_certificates/3/EC de Autenticação do Cartão de Cidadão*.cer'):
		spt = file.split('/')
		cert_name = spt[-1]
	
	cert = open("client_certificates/3/"+cert_name, "rb").read()
	certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert) # OpenSSL.crypto.X509 object at 0x105dbf74

	ctx = cc.get_certificate_keystore()

	trusted_certificates = []
	intermidiate_certificates = []

	trusted_certificates, intermidiate_certificates = cc.load_certificates()
	print(cc.verify_certificate_chain(certificate, intermidiate_certificates))
	"""