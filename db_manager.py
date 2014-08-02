from db_model import TLSScan,TLSConfiguration,CertificateConfiguration,CertificateChain
from db_model import *
from x509certchain import X509CertChain
from x509 import X509
from tls_config import TLSConfig

class DBManager:

    def create_tables(self):
        TLSConfiguration.create_table()
        CertificateConfiguration.create_table()
        CertificateChain.create_table()
        TLSScan.create_table()

    def test_insert(self):
       TLSConfiguration.create(protocol_version="0x0301", ciphersuites="0x000065", compression="0x00")

       obj = CertificateConfiguration.create(serial_number = "0x3456", signature_algorithm="SHAwithRSA", common_name="goskope.com", alternative_name="*.goskope.com", valid_from=datetime.datetime.now(),valid_until = datetime.datetime.now(), key_size="2048", issuer="Digicert", sha1_fingerprint="23847293701832947sdvcxz", key_algorithm="RSA")

       CertificateChain.create(cert_chain_id = 1, cert_id = obj)

    def insert_scan_result(self, TLSConfig, X509CertChain):
        ver = ""
        for v in TLSConfig.tls_versions:
            if v == (2,0):
                ver = ver + "2.0"
            elif v == (3,0):
                ver = ver + "3.0"
            elif v == (3,1):
                ver = ver + "3.1"
            elif v == (3,2):
                ver = ver + "3.2"
            elif v == (3,3):
                ver = ver + "3.3"

            ver = ver + ","

        ciphers = ""
        for cipher_id in TLSConfig.ciphersuites:
            ciphers = ciphers + str(cipher_id) + ","
        print ciphers

        if TLSConfig.compression == 0:
            compression = False
        else:
            compression = True

        tlsconfig = TLSConfiguration.create(protocol_version=ver, ciphersuites=ciphers, compression=compression)

def main():
    mang = DBManager()
    #mang.create_tables()
    #mang.test_insert()

if __name__ == "__main__":
    main()

