"""
TODO
- website does not support ssl message
"""

from utils.constants import *
from utils.packetCreator import *
from operator import itemgetter
import socket,binascii, sys
import time
import copy
#from db_manager import DBManager
from tls_config import TLSConfig

from messages import *


#TLS/SSL handshake RFC2246 pg 31

"""
Format of an SSL record
Byte 0 = SSL record type
Bytes 1-2   = SSL version (major/minor)
Bytes 3-4   = Length of data in the record (excluding the header itself). The maximum SSL supports is 16384 (16K).

Byte 0 can have following values:
    SSL3_RT_CHANGE_CIPHER_SPEC  20  (x'14')
    SSL3_RT_ALERT               21  (x'15')
    SSL3_RT_HANDSHAKE           22  (x'16')
    SSL3_RT_APPLICATION_DATA    23  (x'17')

Bytes 1-2 in the record have the following version values:
    SSL3_VERSION        x'0300'
    TLS1_VERSION        x'0301'

FORMAT OF AN SSL HANDHSAKE RECORD
Byte   0       = SSL record type = 22 (SSL3_RT_HANDSHAKE)
Bytes 1-2      = SSL version (major/minor)
Bytes 3-4      = Length of data in the record (excluding the header itself).
Byte   5       = Handshake type
Bytes 6-8      = Length of data to follow in this record
Bytes 9-n      = Command-specific data


BYTE 5 in the record has the following handhsake type values:
    SSL3_MT_HELLO_REQUEST            0   (x'00')
    SSL3_MT_CLIENT_HELLO             1   (x'01')
    SSL3_MT_SERVER_HELLO             2   (x'02')
    SSL3_MT_CERTIFICATE             11   (x'0B')
    SSL3_MT_SERVER_KEY_EXCHANGE     12   (x'0C'
    SSL3_MT_CERTIFICATE_REQUEST     13   (x'0D')
    SSL3_MT_SERVER_DONE             14   (x'0E')
    SSL3_MT_CERTIFICATE_VERIFY      15   (x'0F')
    SSL3_MT_CLIENT_KEY_EXCHANGE     16   (x'10')
    SSL3_MT_FINISHED                20   (x'14')
"""

class SSLConnection:
    #TODO test for versions supported
    def __init__(self,host,version,port = 443,timeout = 5.0):
        self.clientSocket = None
        self.isClientHello = False
        self.isServerHello = False
        self.isServerCertificate = False
        self.isServerHelloDone = False
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ip = None


    def _doPreHandshake(self):
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientSocket.connect((self.host, self.port))
        self.clientSocket.settimeout(self.timeout)

    def _clientHelloPacket(self, version, ciphersuite):
        cHello = ClientHello()
        session = bytearray(0)
        if ciphersuite is None:
            ciphersuite =copy.copy(CipherSuite.all_suites)

        cHello.create(version, getRandomBytes(32), session, ciphersuite)
        p = bytearray()
        p = cHello.write()
        recordHeader = RecordHeader3().create(version, ContentType.handshake, len(p))
        pkt = recordHeader.write() + p
        return pkt



    #@param parseUntil to stop the parsing when that information is extracted
    # parseUntil  ServerVersion, Compression
    def _readRecordLayer(self,sock,parseUntil):
        b = bytearray(0)
        recordHeaderLength = 1

        while 1:
            try:
                bytes_read = sock.recv(recordHeaderLength - len(b))
                if len(bytes_read) == 0:
                    print "[!] Read 0 bytes from socket"

                b += bytearray(bytes_read)

                if len(b) == 1:
                    if b[0] in ContentType.all:
                        recordHeaderLength = 5
                        if b[0] is ContentType.alert:
                            #print "Got an alert"
                            return
                    else:
                        print "[!] unknown ssl record layer"
                        break
                elif len(b) == recordHeaderLength:
                    break

            except socket.error, msg:
                print "[!] Error in reading from socket because %s" %msg
                break

        #parse the record layer
        recordLayer = RecordHeader3().parse(Parser(b))

        if recordLayer.length > 16384:
            print "[!] Bufferoverflow, record length more than supported"

        #TODO handle case when in one record server hello, cert and server hello done comes

        b = bytearray(0)
        while 1:
            try:
                bytes_read = sock.recv(recordLayer.length - len(b))
                #print recordLayer.length, len(b), len(bytes_read)
            except scoket.error, msg:
                print "[!] Error in reading from socket because %s" %msg

            if len(bytes_read) == 0:
                print "[!] Read 0 bytes from socket"

            b += bytearray(bytes_read)
            if b[0] is HandshakeType.server_hello:
                b = b[1:]
                serverHello = ServerHello().parse(Parser(b))

                if parseUntil is "ServerVersion": return serverHello.server_version
                if parseUntil is "Compression": return serverHello.compression_method

                return serverHello.cipher_suite

            elif b[0] is HandshakeType.certificate:
            #TODO serious hack to fetch all data from socket, need to do fetching in more better way
                if len(b) != recordLayer.length:
                    bytes_read = sock.recv(recordLayer.length - len(b))
                    b += bytearray(bytes_read)

                b = b[1:]
                certificate = Certificate(CertificateType.x509).parse(Parser(b))
                return certificate
                #return certificate
                #print "certtype",len(certificate.certChain.x509List)
                #for x in certificate.certChain.x509List:
                #    print x.subject
                #    print "----"
            elif b[0] is HandshakeType.server_hello_done:
                print "[+] Server hello done"
            else:
                pass
                #print "maza nahi aya"

            if len(b) == recordLayer.length:
                break
        return

    def doClientHello(self, version):
        """
        struct {
            ProtocolVersion client_version;
            Random random;
            SessionID session_id;
            CipherSuite cipher_suites<2..2^16-1>;
            CompressionMethod compression_methods<1..2^8-1>;
            Extension extensions<0..2^16-1>;
            } ClientHello;

        """
        try:
            self._doPreHandshake()
            pkt = _clientHelloPacket(version)

            self.clientSocket.send(pkt)

        except socket.error, msg:
            #TODO handle errors for timeout
            print "[!] Could not connect to target host because %s" %msg
            #TODO return or exit or escalate the exception
        except socket.gaierror, msg:
            print "[!] Check whether website exists. Error:%s" %msg

    def enumerateCiphers(self,version):
        cipherSuitesDetected = []
        cHello = ClientHello()
        cipher_accepted = None
        ciphersuite =copy.copy(CipherSuite.all_suites)
        #ciphersuite = CipherSuite.ecdheSuites

        #get the ciphersuites supported in preference order
        while len(ciphersuite) > 0:
            pkt = self._clientHelloPacket(version, ciphersuite)
            self._doPreHandshake()
            try:
                self.clientSocket.send(pkt)
                cipher = self._readRecordLayer(self.clientSocket, None)
                if cipher in ciphersuite:
                    cipher_accepted = cipher
                    cipher_id = '%06x' % cipher
                    cipher_id = cipher_id.upper() # all names in upper case in constants.py
                    ciphersuite.remove(cipher_accepted)
                    #print len(ciphersuite)
                    if CipherSuite.cipher_suites.has_key(cipher_id):
                        cipherSuitesDetected.append(cipher_id)
                        #print CipherSuite.cipher_suites[cipher_id]['name']
                        self.clientSocket.close()
                else:
                    if cipher is not None:
                        print "[!] Server returned cipher not in ciphersuite %s"%(cipher)
                    break


            except socket.error, msg:
                print "[!] Could not connect to target host because %s" %msg

        return cipherSuitesDetected


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
                if supportedVersion is not None:
                    supportedVersions.append(supportedVersion)
                    #print supportedVersion
                    self.clientSocket.close()

            except socket.error, msg:
                print "[!] Could not connect to target host because %s" %msg

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
            print "[!] Could not connect to target host because %s" %msg

    def scanCertificates(self,host, version):
        cHello = ClientHello()
        ciphersuite =copy.copy(CipherSuite.all_suites)
        #print len(ciphersuite)
        #version = (3,2)
        pkt = self._clientHelloPacket(version, ciphersuite)
        try:
            self._doPreHandshake()
            self.clientSocket.send(pkt)
            # TODO HACK, get server hello
            self._readRecordLayer(self.clientSocket, "Certificate")
            #  HACK get certificate
            certificate = self._readRecordLayer(self.clientSocket, "Certificate")
            self.clientSocket.close()
            for x in certificate.certChain.x509List:
                 x.print_cert()

            return certificate

        except socket.gaierror, msg:
            print "[!] Check whether website exists. Error:%s" %msg

        except socket.error, msg:
            print "[!] Could not connect to target host because %s" %msg
            return None
        except SyntaxError:
            print "[!] Error in fetching certificate, try again later"
            return None

    def getIP(self):
        addr = socket.gethostbyname(self.host)
        self.ip = addr
        return self.ip

def cipherTest(host, version):
    conn = SSLConnection(host,version,443,5.0)
    #Resolve the IP
    print "[+] HOST:",host
    print "[+] IP:", conn.getIP(), " \n"

    sslVersions = conn.enumerateSSLVersions()
    print "\n[+] SSL VERSIONS SUPPORTED:"
    if len(sslVersions)> 0:
        for ver in sslVersions:
            print "     ",ver
    else:
        print "No version detected strangely"

    maxSSLVersion = max(sslVersions, key=itemgetter(1))
    #get the ciphers supported
    cipherSuitesDetected = conn.enumerateCiphers(maxSSLVersion)
    print "\n[+] CIPHERS SUPPORTED IN DEFAULT PREFERRED ORDER:"
    for cipher_id in cipherSuitesDetected:
        print "     " + CipherSuite.cipher_suites[cipher_id]['name']

    print "\n[+] LIST OF POTENTIALLY WEAK CIPHERS:"
    for cipher_id in cipherSuitesDetected:
        if 'RC4' in CipherSuite.cipher_suites[cipher_id]['enc']:
            print "     "+CipherSuite.cipher_suites[cipher_id]['name']

    compression = conn.isCompressionSupported()
    if compression is None:
        print "[-] Error in getting compression value"
    else:
        if compression == 0:
            print "\n[+] COMPRESSION SUPPORT: No"
        else:
            print "\n[+] COMPRESSION SUPPORT: Yes"

    print " \n "
    tls_config = TLSConfig(domain = host,ip= conn.getIP(), tls_versions = sslVersions, ciphersuites = cipherSuitesDetected, compression = compression)

    return tls_config


def certificateTest(host, version):
    version=(3,2)
    connection_obj = SSLConnection(host,version,443,5.0)
    print "[*] CERTIFICATE CHAIN"
    connection_obj.scanCertificates(host, version)


def print_scan_result():
    pass

def main(argv):
    if len(argv) == 1:
        print "[!] Give host and port \n"
    else:
        host = argv[1].strip()
        version = (3,2)
        #tls_config = cipherTest(host, version)
        cipherTest(host, version)
        cert = certificateTest(host, version)
        #db_manager = DBManager()
        #db_manager.insert_scan_result(tls_config, cert)

if __name__ == "__main__":
    main(sys.argv)






