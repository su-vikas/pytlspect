class Result:
    """
    For storing results, parameters like IP, ciphersuits etc and print in desired
    format.
    """
    def __init__(self, host=None, IP= None):
        self.host = host
        self.IP = IP
        self.sslVersions = None         # tls versions supported
        self.maxSSLVersion = None
        self.supportedCiphers = None    # a dictionary {'version':'[cipher list]'}
        self.weakCiphers = None         # list of weak ciphers
        self.isCompression = None       # is compression supported.

        # certificate chain
        self.certChainLength = None
        self.certChain = None

        self.isPoodle = None
        self.isHeartbleed = None
        self.isCCS =  None

    def __str__(self):
        if self.sslVersions:
            self.printSSLVersions

        if self.supportedCiphers:
            self.printCipherSuites

        if self.isCompression:
            if compression is None:
                print "[-] Error in getting compression value"
            else:
                if compression == 0:
                    print "\n[+] COMPRESSION SUPPORT: No"
                else:
                    print "\n[+] COMPRESSION SUPPORT: Yes"

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


