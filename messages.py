from utils.packetCreator import *
from utils.constants import *
from utils.cryptomath import *
from utils.codec import *
from x509 import *
from x509certchain import *
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

"""

class RecordHeader3(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = False


    def create(self,version, type, length):
        self.type = type
        self.version = version
        self.length = length
        return self

    def write(self):
        w = Writer()
        w.add(self.type, 1)
        w.add(self.version[0], 1)
        w.add(self.version[1], 1)
        w.add(self.length, 2)
        return w.bytes

    def parse(self, p):
        self.type = p.get(1)
        self.version = (p.get(1), p.get(1))
        self.length = p.get(2)
        self.ssl2 = False
        return self


class RecordHeader2(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = True

#TODO parse fucntion not included
"""
FORMAT OF AN SSL HANDHSAKE RECORD
Byte   0       = SSL record type = 22 (SSL3_RT_HANDSHAKE)
Bytes 1-2      = SSL version (major/minor)
Bytes 3-4      = Length of data in the record (excluding the header itself).
Byte   5       = Handshake type
Bytes 6-8      = Length of data to follow in this record
Bytes 9-n      = Command-specific data
"""

class HandshakeMsg(object):
    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType

    def postWrite(self,w):
        headerWriter = Writer()
        headerWriter.add(self.handshakeType, 1)
        headerWriter.add(len(w.bytes), 3)
        return headerWriter.bytes + w.bytes

"""
Client hello as per RFC

struct {
    ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites<2..2^16-1>;
    CompressionMethod compression_methods<1..2^8-1>;
    Extension extensions<0..2^16-1>;
} ClientHello;
"""
class ClientHello(HandshakeMsg):
    def __init__(self, ssl2=False):
        HandshakeMsg.__init__(self, HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []         # list of 16-bit values
        self.certificate_types = [CertificateType.x509]
        self.compression_methods = []   # list of 8-bit values
        self.srp_username = None        # string
        self.tack = False               # TLS key pinning for everyone http://lwn.net/Articles/499134/
        self.supports_npn = False
        self.server_name = bytearray(0) # for Server Name Indication (SNI)

    def create(self, version, random, session_id, cipher_suites, certificate_types = None, srpUsername=None,
                tack=False, supports_npn=False, serverName=None):
        self.client_version = version
        self.random = random
        self.session_id = session_id   #THis field should be empty if no session_id is available or the client wishes to generate new security parameters
        self.cipher_suites = cipher_suites
        self.certificate_types = certificate_types
        self.compression_methods = [0,1,64]
        if srpUsername:
            self.srp_username = bytearray(srpUsername, "utf-8")

        self.tack = tack
        self.supports_npn = supports_npn
        if serverName:
            self.server_name = bytearray(serverName, "utf-8")
        return self

    def write(self):
        w = Writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.session_id, 1, 1)
        w.addVarSeq(self.cipher_suites, 2, 2)
        w.addVarSeq(self.compression_methods, 1, 1)

        #TODO read about extensions
        w2 = Writer()       # for extensions
        if self.certificate_types and self.certificate_types != [CertificateType.x509]:
            w2.add(ExternsionType.cert_type, 2)
            w2.add(len(self.certificate_types)+1,2)
            w2.addVarSeq(self.certificate_types, 1, 1)

        if self.srp_username:
            w2.add(ExtensionType.srp, 2)
            w2.add(len(self.srp_username)+1, 2)
            w2.addVarSeq(self.srp_username, 1, 1)

        if self.supports_npn:
            w2.add(ExtensionType.supports_npn, 2)
            w2.add(0, 2)

        if self.server_name:
            w2.add(ExtensionType.server_name, 2)
            w2.add(len(self.server_name)+5, 2)
            w2.add(len(self.server_name)+3, 2)
            w2.add(NameType.host_name, 1)
            w2.addVarSeq(self.server_name, 1, 2)

        if self.tack:
            w2.add(ExtensionType.tack, 2)
            w2.add(0, 2)

        if len(w2.bytes):
            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return self.postWrite(w)

"""
RFC 5246 pg 41
struct {
          ProtocolVersion server_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suite;
          CompressionMethod compression_method;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ServerHello;
"""

class ServerHello(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello)
        self.server_version = (0,0)    # lower of that suggested by the client in the client hello and the highest supported by the server.
        self.random = bytearray(32)   # random generated by server, independent of clienthello.random
        self.session_id = bytearray(0) # if returned empty, implies session will not be cached
        self.cipher_suite = 0
        self.certificate_type = CertificateType.x509
        self.compression_method = 0
        self.tackExt = None
        self.next_protos_advertised = None
        self.next_protos = None
        self.server_name = False


    def create(self, version, random, session_id, cipher_suite, certificate_type, tackExt, next_protos_advertised):
        self.server_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type
        self.compression_method = 0
        self.tackExt = tackExt
        self.next_protos_advertised = next_protos_advertised
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.server_version = (p.get(1), p.get(1))
        self.random = p.getFixBytes(32)
        self.session_id = p.getVarBytes(1)
        self.cipher_suite = p.get(2)
        self.compression_method = p.get(1)

        #TODO whats going on over here
        if not p.atLengthCheck():
            totalExtLength = p.get(2)
            soFar = 0
            while soFar != totalExtLength:
                extType = p.get(2)
                extLength = p.get(2)
                if extType == ExtensionType.cert_type:
                    if extLength != 1:
                        raise SyntaxError()
                    self.certificate_type = p.get(1)
                elif extType == ExtensionType.tack and tackpyLoaded:
                    self.tackExt = TackExtension(p.getFixBytes(extLength))
                elif extType == ExtensionType.supports_npn:
                    self.next_protos = self.__parse_next_protos(p.getFixBytes(extLength))
                elif extType == ExtensionType.server_name:
                    self.server_name = True
                else:
                    p.getFixBytes(extLength)
                soFar += 4 + extLength
        p.stopLengthCheck()
        return self


    def __parse_next_protos(self, b):
        protos = []
        while True:
            if len(b) == 0:
                break
            l = b[0]
            b = b[1:]
            if len(b) < l:
                raise BadNextProtos(len(b))
            protos.append(b[:l])
            b = b[l:]
        return protos

    def __next_protos_encoded(self):
        b = bytearray()
        for e in self.next_protos_advertised:
            if len(e) > 255 or len(e) == 0:
                raise BadNextProtos(len(e))
            b += bytearray( [len(e)] ) + bytearray(e)
        return b

class Certificate(HandshakeMsg):
    def __init__(self, certificateType):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self.certChain = None

    def create(self, certChain):
        self.certChain = certChain
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.certificateType == CertificateType.x509:
            chainLength = p.get(3)
            index = 0
            certificate_list = []
            while index != chainLength:
                certBytes = p.getVarBytes(3)
                x509 = X509()
                x509.parseBinary(certBytes)
                certificate_list.append(x509)
                index += len(certBytes)+3
            if certificate_list:
                self.certChain = X509CertChain(certificate_list)
        else:
            raise AssertionError()

        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.certificateType == CertificateType.x509:
            chainLength = 0
            if self.certChain:
                certificate_list = self.certChain.x509List
            else:
                certificate_list = []
            #determine length
            for cert in certificate_list:
                bytes = cert.writeBytes()
                chainLength += len(bytes)+3
            #add bytes
            w.add(chainLength, 3)
            for cert in certificate_list:
                bytes = cert.writeBytes()
                w.addVarSeq(bytes, 1, 3)
        else:
            raise AssertionError()
        return self.postWrite(w)

class ChangeCipherSpec(object):
    def __init__(self):
        self.contentType = ContentType.change_cipher_spec
        self.type = 1

    def create(self):
        self.type = 1
        return self

    def parse(self,p):
        p.setLengthCheck(1)
        self.type = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.type, 1)
        return w.bytes

class Alert(object):
    def __init__(self):
        self.contentType = ContentType.alert
        self.level = 0
        self.description = 0

    def create(self,description, level=AlertLevel.fatal):
        self.level = level
        self.description = description
        return self

    def parse(self,p):
        p.setLengthCheck(2)
        self.level = p.get(1)
        self.description = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.level, 1)
        w.add(self.description,1)
        return w.bytes
