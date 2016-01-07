class Result(object):
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
        self.printSSLVersions()
        self.printCompression()
        self.printTLSExtensions()
        self.printCertificates()
        self.printPoodle()

    def updateCiphers(self, version, cipherSuitesDetected):
        """
            updates the dictionary object mapping ssl versions detected and
            correspdonding ciphersDetected
        """
        if not self.supportedCiphers:
            self.supportedCiphers = {}

        if version not in self.supportedCiphers:
            self.supportedCiphers[version] = []
            self.supportedCiphers[version] += cipherSuitesDetected

        else:
            self.supportedCiphers[version] += cipherSuitesDetected

    def printSSLVersions(self):
        """
            print ssl versions detected to stdout
        """
        TLSVersion = "[*] TLS versions supported: "
        if self.isSSLV3:
            TLSVersion += "SSLv3"
        if self.isTLSV10:
            TLSVersion += " TLSv1.0"
        if self.isTLSV11:
            TLSVersion += " TLSv1.1"
        if self.isTLSV12:
            TLSVersion += " TLSv1.2"

        print TLSVersion

    def printCompression(self):
        if all(x > 0 for x in (self.isCompressionSSLV3, self.isCompressionTLSV10, \
                self.isCompressionTLSV11, self.isCompressionTLSV12)):
            print "\n[*] COMPRESSION SUPPORT: Yes"
        else:
            print "\n[*] COMPRESSION SUPPORT: No"

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

    def printTLSExtensions(self):
        """
            Print TLS Extensions supported.
        """
        print "\n[*] TLS EXTENSIONS Supported: "
        if self.extensionsSSLV3:
            for key, value in self.extensionsSSLV3.iteritems():
                print "     SSLv3: ", str(key)
            print "\n"

        if self.extensionsTLSV10:
            for key, value in self.extensionsTLSV10.iteritems():
                print "     TLSv1.0: ", str(key)
            print "\n"

        if self.extensionsTLSV11:
            for key, value in self.extensionsTLSV11.iteritems():
                print "     TLSv1.1: ", str(key)
            print "\n"

        if self.extensionsTLSV12:
            for key, value in self.extensionsTLSV12.iteritems():
                print "     TLSv1.2: ", str(key)
            print "\n"

    def printCertificates(self):
        print "[*] CERTIFICATE CHAIN \n"
        if self.certChain:
            for x in self.certChain.certChain.x509List:
                 x.print_cert()

    def printIP(self):
        """ print IP for the host """
        print "[+] HOST:", self.host
        print "[+] IP:", self.IP, "\n"

    def printPoodle(self):
        """
            Prints results for POODLE.
        """
        if self.isPoodle:
            print "[*] Vulnerable to SSLv3 POODLE: Yes"
        else:
            print "[*] Vulnerable to SSLv3 POODLE: No"

class MetaResult(object):
    """
        Class encapsulates the meta information about the scan.
    """
    def __init__(self):
        self.startTime = None
        self.stopTime = None
        self.countConnections = None

