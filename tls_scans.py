
class TLSScans(object):
    """
        Encapsulates all the scans to be performed.
    """

    def enumerateCiphers(self, version, customCipherSuite = None):
        cipherSuitesDetected = []
        cHello = ClientHello()
        cipher_accepted = None
        cipherSuite = None
        if customCipherSuite:
            cipherSuite = copy.copy(customCipherSuite)
        else:
            cipherSuite =copy.copy(CipherSuite.all_suites)

        #get the ciphersuites supported in preference order
        while len(cipherSuite) > 0:
            pkt = self._clientHelloPacket(version, cipherSuite)
            self._doPreHandshake()
            try:
                self.clientSocket.send(pkt)
                cipher = self._readRecordLayer(self.clientSocket, None)
                if cipher in cipherSuite :
                    cipher_accepted = cipher
                    cipher_id = '%06x' % cipher
                    cipher_id = cipher_id.upper() # all names in upper case in constants.py
                    cipherSuite.remove(cipher_accepted)
                    #print len(ciphersuite)
                    if CipherSuite.cipher_suites.has_key(cipher_id):
                        cipherSuitesDetected.append(cipher_id)
                        #print CipherSuite.cipher_suites[cipher_id]['name']
                        self.clientSocket.close()
                else:
                    # server returns alert, when no ciphersuits match
                    if "Alert" in cipher:
                        break

                    elif cipher is not None:
                        raise TLSError("[!] Server returned cipher not in ciphersuite")
                    break


            except socket.error, msg:
                raise TLSError("[!] Could not connect to target host")

        return cipherSuitesDetected

    # VERSION TESTS
    def _checkSSLVersion(self):
        """
            Send the client hello message.
        """
        try:
            # TODO fix the supported version issue
            self.clientSocket.send(pkt)
            supportedVersion = self._readRecordLayer(self.clientSocket,"ServerVersion")
            if supportedVersion is not None and "Alert" not in supportedVersion:
                return supportedVersion
                #print supportedVersion
                self.clientSocket.close()
        except socket.error, msg:
            raise TLSError("[!] Could not connect to target host")

    def _isSSLV3Supported(self):
        """
            Checks if the sslv3 supported by the remote server.
        """
        settings = HandshakeSettings()
        settings.maxVersion = (3,0)
        settings.minVersion = (3,0)
        # TODO fix this. Only send minimum suites to reduce bandwidth
        settings.cipherSuites = copy.copy(CipherSuite.all_suites)


    def enumerateSSLVersions(self):
        cHello = ClientHello()
        ciphersuite =copy.copy(CipherSuite.all_suites)
        supportedVersions = []

        sslVersions = [(3,0),(3,1),(3,2),(3,3)]
        #loop for ssl versions
        for ver in sslVersions:
            pkt = self._clientHelloPacket(ver, ciphersuite)
            self._doPreHandshake()

            try:
                self.clientSocket.send(pkt)
                supportedVersion = self._readRecordLayer(self.clientSocket,"ServerVersion")
                if supportedVersion is not None and "Alert" not in supportedVersion:
                    supportedVersions.append(supportedVersion)
                    #print supportedVersion
                    self.clientSocket.close()

            except socket.error, msg:
                raise TLSError("[!] Could not connect to target host")
                #print "[!] Could not connect to target host because %s" %msg

        return supportedVersions

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

