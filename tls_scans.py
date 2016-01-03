from handshake_settings import HandshakeSettings
from ssl_connection import SSLConnection
from utils.constants import SSLVersions
from cert_checker import CertChecker
from result import Result
from errors import *

class TLSScans(object):
    """
        Encapsulates all the scans to be performed.
    """

    def __init__(self, host, result):
        self.settings = HandshakeSettings(host)
        self.result = result

        self.isCertificate = False     # to maintain state if certificates has been parsed.

    def startHandshake(self, settings):
        """
            Checks if the sslv3 supported by the remote server.
        """
        connection = SSLConnection(settings)
        result = connection.startHandshake(settings)
        return result

    def _parseExtensions(self, serverHello):
        extensions = {}
        if serverHello.next_protos:
            extensions['next_protocol_negotiation'] = [e for e in serverHello.next_protos]
        if serverHello.server_name:
            extensions['server_name'] = True
        if serverHello.tackExt:
            extensions['tack'] = True
        if serverHello.renegotiation_info:
            extensions['renegotiation_info'] = True
        if serverHello.heartbeat:
            extensions['Heartbeat'] = True
        if serverHello.ocsp:
            extensions['status_request'] = True
        if serverHello.session_ticket:
            extensions['SessionTicket TLS'] = True
        if serverHello.ec_point_formats:
            extensions['ec_point_formats'] = True

        return extensions

    def _parseCertificate(self, serverCertificate):

        if not self.isCertificate:
            checker = CertChecker(self.settings.host, serverCertificate)
            checker.checkExpiryDate()
            self.result.certChain = serverCertificate

            self.isCertificate = True

    def getSSLV3Params(self):
        """
            Gets all the parameters for SSLv3.
        """
        self.settings.version = SSLVersions.SSLV3
        try:
            result = self.startHandshake(self.settings)
            if result:
                serverHello, serverCertificate = result
                self.result.isCompressionSSLV3 = serverHello.compression_method
                if self.settings.version == serverHello.server_version:
                    self.result.isSSLV3 = True

                self.result.extensionsSSLV3 = self._parseExtensions(serverHello)

                self._parseCertificate(serverCertificate)
        except TLSRemoteAlert:
            #TODO add logging.
            pass

    def getTLSV10Params(self):
        """
            Gets all the parameters for SSLv3.
        """
        self.settings.version = SSLVersions.TLSV10
        result = self.startHandshake(self.settings)
        if result:
            serverHello, serverCertificate = result
            self.result.isCompressionTLSV10 = serverHello.compression_method
            if self.settings.version == serverHello.server_version:
                self.result.isTLSV10 = True

            self.result.extensionsTLSV10 = self._parseExtensions(serverHello)
            self._parseCertificate(serverCertificate)

    def getTLSV11Params(self):
        """
        """
        self.settings.version = SSLVersions.TLSV11
        result = self.startHandshake(self.settings)
        if result:
            serverHello, serverCertificate = result
            self.result.isCompressionTLSV11 = serverHello.compression_method
            if self.settings.version == serverHello.server_version:
                self.result.isTLSV11 = True

            self.result.extensionsTLSV11 = self._parseExtensions(serverHello)
            self._parseCertificate(serverCertificate)

    def getTLSV12Params(self):
        self.settings.version = SSLVersions.TLSV12
        result = self.startHandshake(self.settings)
        if result:
            serverHello, serverCertificate = result
            self.result.isCompressionTLSV12 = serverHello.compression_method
            if self.settings.version == serverHello.server_version:
                self.result.isTLSV12 = True

            self.result.extensionsTLSV12 = self._parseExtensions(serverHello)
            self._parseCertificate(serverCertificate)

    def getAllParams(self):
        self.getSSLV3Params()
        self.getTLSV10Params()
        self.getTLSV11Params()
        self.getTLSV12Params()

    def getIP(self):
        addr = socket.gethostbyname(self.host)
        self.ip = addr
        return self.ip

    def getIPs(self):
        addr = socket.gethostbyname(self.host)
        self.ip = addr
        return self.ip

def main():
    host = "www.facebook.com"
    result = Result(host)
    scan = TLSScans(host, result)
    scan.getAllParams()
    result.output()
    result.printCertificates()

if __name__ == "__main__":
    main()

