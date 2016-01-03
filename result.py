class Result:
    """
    For storing results, parameters like IP, ciphersuits etc and print in desired
    format.
    """
    def __init__(self, host=None, IP= None):
        self.host = host
        self.IP = IP
        self.isSSLV3 = False
        self.isCompressionSSLV3  = False
        self.extensionsSSLV3 = {}

        self.isTLSV10 = False
        self.isCompressionTLSV10 = False
        self.extensionsTLSV10 = {}

        self.isTLSV11 = False
        self.isCompressionTLSV11 = False
        self.extensionsTLSV11 = {}

        self.isTLSV12 = False
        self.isCompressionTLSV12 = False
        self.extensionsTLSV12 = {}

        self.supportedCiphers = None    # a dictionary {'version':'[cipher list]'}
        self.weakCiphers = None         # list of weak ciphers

        # certificate chain
        self.certChainLength = None
        self.certChain = None

        self.isPoodle = None
        self.isHeartbleed = None
        self.isCCS =  None

    def output(self):
        TLSVersion = "[+] TLS versions supported: "
        if self.isSSLV3:
            TLSVersion += "SSLv3"
        if self.isTLSV10:
            TLSVersion += " TLSv1.0"
        if self.isTLSV11:
            TLSVersion += " TLSv1.1"
        if self.isTLSV12:
            TLSVersion += " TLSv1.2"

        print TLSVersion

        if self.isCompressionSSLV3 or self.isCompressionTLSV10 or \
                self.isCompressionTLSV11 or self.isCompressionTLSV12:
            print "\n[+] COMPRESSION SUPPORT: Yes"
        else:
            print "\n[+] COMPRESSION SUPPORT: No"

        print "[+] EXTENSIONS Supported: "
        if self.extensionsSSLV3:
            print "     SSLv3: ", str(self.extensionsSSLV3)

        if self.extensionsTLSV10:
            print "     TLSv1.0: ", str(self.extensionsTLSV10)

        if self.extensionsTLSV11:
            print "     TLSv1.1: ", str(self.extensionsTLSV11)

        if self.extensionsTLSV12:
            print "     TLSv1.2: ", str(self.extensionsTLSV12)

    def updateCiphers(self, version, cipherSuitesDetected):
        """ updates the dictionary object mapping ssl versions detected and
        correspdonding ciphersDetected"""
        if not self.supportedCiphers:
            self.supportedCiphers = {}

        if version not in self.supportedCiphers:
            self.supportedCiphers[version] = []
            self.supportedCiphers[version] += cipherSuitesDetected

        else:
            self.supportedCiphers[version] += cipherSuitesDetected

    def printCipherSuites(self):
        if not self.supportedCiphers:
            print "[+] No ciphers scanned for "
        else:
            print "\n[+] CIPHERS SUPPORTED IN DEFAULT PREFERRED ORDER:"
            for keys, value in self.supportedCiphers.iteritems():
                print "\n     [+] TLS Version:", keys
                if value:
                    for c in value:
                        print "         " + c

    def printSSLVersions(self):
        """ print ssl versions detected to stdout"""

        print "\n[+] SSL VERSIONS SUPPORTED:"
        if len(self.sslVersions)> 0:
            for ver in self.sslVersions:
                print "     ",ver
        else:
            print "No version detected strangely"

    def printIP(self):
        """ print IP for the host """
        print "[+] HOST:", self.host
        print "[+] IP:", self.IP, "\n"

    def printCompression(self):
        if self.isCompression is None:
            print "[-] Error in getting compression value"
        else:
            if self.isCompression == 0:
                print "\n[+] COMPRESSION SUPPORT: No"
            else:
                print "\n[+] COMPRESSION SUPPORT: Yes"
        print " \n "

    def printCertificates(self):
        print "[*] CERTIFICATE CHAIN"
        if self.certChain:
            for x in self.certChain.certChain.x509List:
                 x.print_cert()


