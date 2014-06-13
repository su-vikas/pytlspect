from utils.constants import *
from utils.packetCreator import *
import socket,binascii, sys
from messages import *
import pdb


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

    def _doPreHandshake(self):
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientSocket.connect((self.host, self.port))
        self.clientSocket.settimeout(self.timeout)

    def _clientHelloPacket(self, version, cipherSuite):
        cHello = ClientHello()
        session = bytearray(0)
        if cipherSuite is None:
            cipherSuite = CipherSuite.all

        cHello.create(version, getRandomBytes(32), session, cipherSuite)
        p = bytearray()
        p = cHello.write()
        recordHeader = RecordHeader3().create(version, ContentType.handshake, len(p))
        pkt = recordHeader.write() + p
        return pkt


    def _readRecordLayer(self,sock):
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
                            print "Got an alert"
                            return
                    else:
                        print "[!] unknown ssl recor layer"
                elif len(b) == recordHeaderLength:
                    break

            except scoket.error, msg:
                print "[!] Error in reading from socket because %s" %msg

        #parse the record layer
        recordLayer = RecordHeader3().parse(Parser(b))

        if recordLayer.length > 16384:
            print "[!] Bufferoverflow, record length more than supported"

        #TODO handle case when in one record server hello, cert and server hello done comes

        b = bytearray(0)
        while 1:
            try:
                bytes_read = sock.recv(recordLayer.length - len(b))
            except scoket.error, msg:
                print "[!] Error in reading from socket because %s" %msg

            if len(bytes_read) == 0:
                print "[!] Read 0 bytes from socket"

            b += bytearray(bytes_read)
            if b[0] is HandshakeType.server_hello:
                b = b[1:]
                serverHello = ServerHello().parse(Parser(b))
                return serverHello.cipher_suite
            elif b[0] is HandshakeType.certificate:
                certificate = Certificate().parse(Parser(b))
            elif b[0] is HandshakeType.server_hello_done:
                print "[+] Server hello done"

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
        self._doPreHandshake()
        pkt = _clientHelloPacket(version)

        try:
            self.clientSocket.send(pkt)

        except socket.error, msg:
            #TODO handle errors for timeout
            print "[!] Could not connect to target host because %s" %msg
            #TODO return or exit or escalate the exception

    def enumerateCiphers(self,version):
        cHello = ClientHello()
        #ciphersuite=CipherSuite.aes256Suites
        cipher_accepted = None
        ciphersuite = CipherSuite.all_suites

        #get the ciphersuites supported in preference order
        while len(ciphersuite) > 0:
            pkt = self._clientHelloPacket(version, ciphersuite)
            self._doPreHandshake()
            try:
                self.clientSocket.send(pkt)
                cipher = self._readRecordLayer(self.clientSocket)
                if cipher in ciphersuite:
                    cipher_accepted = cipher
                    cipher_id = '%06x' % cipher
                    ciphersuite.remove(cipher_accepted)
                    #print len(ciphersuite)
                    if CipherSuite.cipher_suites.has_key(cipher_id):
                        print CipherSuite.cipher_suites[cipher_id]['name']
                        self.clientSocket.close()
                else:
                    print "[!] Server returned cipher not in ciphersuite"
                    break


            except socket.error, msg:
                print "[!] Could not connect to target host because %s" %msg


def main(argv):
    if len(argv) == 1:
        print "[!] GIve host and port \n"
    else:
        host = argv[1].strip()
        version = (3,1)
        conn = SSLConnection(host,version,443,5.0)
        conn.enumerateCiphers(version)

if __name__ == "__main__":
    main(sys.argv)






