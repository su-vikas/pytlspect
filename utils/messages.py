from .utils.packetCreator import *
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
#TODO parse function not included

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
        self.compression_methods = [0]
        if srpUsername:
            self.srp_username = bytearray(srpUsername, "utf-8")

        self.tack = tack
        self.supports_npn = supports_npn
        if serverName:
            self.server_name = bytearray(serverName, "utf-8")
        return self

#TODO parse not included
    def write(self):
        w = writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.sesion_id, 1, 1)
        w.addVarSeq(self.cipher_suites, 2, 2)
        w.addVarSeq(self.copmression_methods, 1, 1)

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





