import sys
from lxml import etree
from signxml import XMLSigner, methods, SignatureMethod, DigestAlgorithm, CanonicalizationMethod
from signxml.xades import XAdESSigner

d = sys.argv[1]
rsa_key, rsa_cert = open(d+'/rsa.key','rb').read(), open(d+'/rsa.pem','rb').read()
ec_key, ec_cert = open(d+'/ec.key','rb').read(), open(d+'/ec.pem','rb').read()

def write(name, tree):
    open(d+'/'+name,'wb').write(etree.tostring(tree, xml_declaration=True, encoding='UTF-8'))

doc = lambda: etree.fromstring(b'<solicitud xmlns="urn:example:sede"><asunto>Licencia de obra</asunto><importe moneda="EUR">120.50</importe></solicitud>')

write('signxml-enveloped-c14n11.xml', XMLSigner(method=methods.enveloped).sign(doc(), key=rsa_key, cert=rsa_cert))
write('signxml-enveloped-exc.xml', XMLSigner(method=methods.enveloped,
    signature_algorithm=SignatureMethod.RSA_SHA512, digest_algorithm=DigestAlgorithm.SHA384,
    c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0).sign(doc(), key=rsa_key, cert=rsa_cert))
write('signxml-enveloping-ecdsa.xml', XMLSigner(method=methods.enveloping,
    signature_algorithm=SignatureMethod.ECDSA_SHA256,
    c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0).sign(doc(), key=ec_key, cert=ec_cert))
write('signxml-xades-enveloped.xml', XAdESSigner(c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0).sign(doc(), key=rsa_key, cert=rsa_cert))
