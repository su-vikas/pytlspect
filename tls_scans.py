from handshake_settings import HandshakeSettings
from ssl_connection import SSLConnection

class TLSScans(object):
    """
        Encapsulates all the scans to be performed.
    """

    def __init__(self, host):
        self.settings = HandshakeSettings(host)

    def _getSSLVersion(self, settings):
        """
            Checks if the sslv3 supported by the remote server.
        """
        try:
            connection = SSLConnection(settings)
            connection.startHandshake(settings)
            return True
        except:
            #TODO catch the exceptions explicitly
            return False

    def enumerateSSLVersions(self):
        """
            Enumerate all the TLS/SSL versions supported by the remote server.
        """
        print self.settings.host
        self.settings.version = (3,0)
        sslv3 = self._getSSLVersion(self.settings)
        print sslv3

        self.settings.version = (3,1)
        tlsv10 = self._getSSLVersion(self.settings)
        print tlsv10

        self.settings.version = (3,2)
        tlsv11 = self._getSSLVersion(self.settings)
        print tlsv11

        self.settings.version = (3,3)
        tlsv12 = self._getSSLVersion(self.settings)
        print tlsv12

    def isCompressionSupported(self):
        cHello = ClientHello()
        ciphersuite =copy.copy(CipherSuite.all_suites)
        version=(3,1)
        pkt = self._clientHelloPacket(version, ciphersuite)
        self._doPreHandshake()

        try:
            self.clientSocket.send(pkt)
            compressionSupported = self._readRecordLayer(self.clientSocket,"Compression")
            self.clientSocket.close()
            return compressionSupported

        except socket.error, msg:
            raise TLSError("[!] Could not connect to target host")
            #print "[!] Could not connect to target host because %s" %msg

    def scanCertificates(self, version):
        cHello = ClientHello()
        ciphersuite =copy.copy(CipherSuite.all_suites)
        pkt = self._clientHelloPacket(version, ciphersuite)
        try:
            self._doPreHandshake()
            self.clientSocket.send(pkt)
            # TODO HACK, get server hello
            self._readRecordLayer(self.clientSocket, "Certificate")
            #  HACK get certificate
            certificate = self._readRecordLayer(self.clientSocket, "Certificate")
            self.clientSocket.close()
            return certificate

        except socket.gaierror, msg:
            raise TLSError("[!] Could not connect to target host, check whether the domain entered is correct")

        except socket.error, msg:
            raise TLSError("[!] Could not connect to target host")
        except SyntaxError as err:
            raise TLSError("[!] Could not connect to target host")

    def supportedExtensions(self):
        # Check for all supported extensions
        cHello = ClientHello()
        ciphersuite =copy.copy(CipherSuite.all_suites)
        #TODO fix the version usage
        version=(3,1)
        pkt = self._clientHelloPacket(version, ciphersuite)
        try:
            self._doPreHandshake()
            self.clientSocket.send(pkt)
            server_hello = self._readRecordLayer(self.clientSocket, "Extensions")

            if server_hello is None:
                print "[!] Error in getting Server Hello. Try again later."
            else:
                print "\n[*] TLS EXTENSIONS SUPPORTED"
                if server_hello.next_protos:
                    print "[+] Next protocol negotiation supported:"
                    for e in server_hello.next_protos:
                        print "     [+]",e
                if server_hello.server_name:
                    print "[+] SNI Supported"
                if server_hello.tackExt:
                    print "[+] Tack supported"
                if server_hello.renegotiation_info:
                    print "[+] Renegotiation supported"
                if server_hello.heartbeat:
                    print "[+] Heartbeat supported"
                if server_hello.ocsp:
                    print "[+] OCSP stapling supported"
                if server_hello.session_ticket:
                    print "[+] Session Ticket TLS supported"
                if server_hello.ec_point_formats:
                    print "[+] Ec Point formats supported"

        except socket.gaierror, msg:
            print "[!] Check whether website exists. Error:%s" %msopenhage

        except socket.error, msg:
            print "[!] Could not connect to target host because %s" %msg
            return None
        except SyntaxError:
            print "[!] Error in fetching certificate, try again later"

    def getIP(self):
        addr = socket.gethostbyname(self.host)
        self.ip = addr
        return self.ip

    def getIPs(self):
        addr = socket.gethostbyname(self.host)
        self.ip = addr
        return self.ip

def main():
    scan = TLSScans("www.google.com")
    scan.enumerateSSLVersions()

if __name__ == "__main__":
    main()

