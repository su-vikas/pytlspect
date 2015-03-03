import datetime
from x509 import X509
from x509certchain import X509CertChain
from errors import *

class CertChecker(object):
    """
    Class to check the validity of the certificates presented by the server
    during handshake.
    """
    def __init__(self, host, cert_chain):
        self.cert_chain = cert_chain
        self.host = host

    def checkExpiryDate(self):
        """ validate the expiry date """
        date_now = datetime.datetime.now()
        for cert in self.cert_chain.certChain.x509List:
            if cert.validFrom > date_now:
                print "Certificate is valid from future date"

            if cert.validUntil < date_now:
                print "Certificate has Expired", cert.validUntil

    def checkSubject(self):
        pass

    def checkSignature(self):
        pass


