from utils.constants import *
from utils.packetCreator import *
from operator import itemgetter
import socket, sys
import copy
import argparse
from errors import *
#from db_manager import DBManager
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
    def __init__(self, settings):
        self.sock = None
        self.host = settings.host
        self.port = settings.port
        self.timeout = settings.timeout
        self.ips = []

        # TO maintain state
        self.isClientHello = False
        self.isServerHello = False
        self.isServerCertificate = False
        self.isServerHelloDone = False

        # To make tlslite functions work over here.
        self._handshakeBuffer = []
        self._client = True

    def _initSocket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(self.timeout)

    # CLIENT HELLO

    def _clientHelloPacket(self, settings):
        """
            Constructs client Hello packet. The first packet sent to initiate handshake.
        """
        cHello = ClientHello()
        session = bytearray(0)
        if settings.cipherSuites is None:
            cipherSuite =copy.copy(CipherSuite.all_suites)
        else:
            cipherSuite = settings.cipherSuites

        cHello.create(settings.version, getRandomBytes(32), session,\
                cipherSuite, serverName = self.host, tack=settings.tack, \
                supports_npn=settings.supports_npn , heartbeat=settings.heartbeat, \
                ocsp=settings.ocsp, session_ticket=settings.session_ticket, \
                elliptic_curves=settings.elliptic_curves, ec_point_formats=settings.ec_point_formats)
        p = bytearray()
        p = cHello.write()
        recordHeader = RecordHeader3().create(settings.version, ContentType.handshake, len(p))
        pkt = recordHeader.write() + p
        return pkt

    def startHandshake(self, settings):
        """
            Starts the handshake process. Sends the client hello and waits for server response and parses the response.
        """
        try:
            cHello = ClientHello()
            cipherSuite = CipherSuite.poodleTestSuites
            self._initSocket()
            pkt = self._clientHelloPacket(settings)
            self.sock.send(pkt)

            # check for server hello
            for result in self._getMsg(ContentType.handshake, HandshakeType.server_hello):
                # TODO what are possible results returned.
                continue
            serverHello = result

            # get server certificate
            for result in self._getMsg(ContentType.handshake, HandshakeType.certificate, CertificateType.x509):
                # TODO what are possible results returned.
                continue
            serverCertificate = result

            # TODO close the connection
            return (serverHello, serverCertificate)

        except socket.error, msg:
            raise TLSError("[!] Could not connect to target host")

        except socket.gaierror, msg:
            raise #TODO did for poodle

    # PARSE INCOMING PACKETS

    def _getMsg(self, expectedType, secondaryType=None, constructorType=None):
        try:
            if not isinstance(expectedType, tuple):
                expectedType = (expectedType,)

            #Spin in a loop, until we've got a non-empty record of a type we
            #expect.  The loop will be repeated if:
            #  - we receive a renegotiation attempt; we send no_renegotiation,
            #    then try again
            #  - we receive an empty application-data fragment; we try again
            while 1:
                for result in self._getNextRecord():
                    if result in (0,1):
                        yield result
                recordHeader, p = result

                #If this is an empty application-data fragment, try again
                if recordHeader.type == ContentType.application_data:
                    if p.index == len(p.bytes):
                        continue

                #If we received an unexpected record type...
                if recordHeader.type not in expectedType:

                    #If we received an alert...
                    if recordHeader.type == ContentType.alert:
                        alert = Alert().parse(p)

                        #We either received a fatal error, a warning, or a
                        #close_notify.  In any case, we're going to close the
                        #connection.  In the latter two cases we respond with
                        #a close_notify, but ignore any socket errors, since
                        #the other side might have already closed the socket.
                        if alert.level == AlertLevel.warning or \
                           alert.description == AlertDescription.close_notify:

                            #If the sendMsg() call fails because the socket has
                            #already been closed, we will be forgiving and not
                            #report the error nor invalidate the "resumability"
                            #of the session.
                            if alert.description == \
                                   AlertDescription.close_notify:
                                self._shutdown(True)
                            elif alert.level == AlertLevel.warning:
                                self._shutdown(False)

                        else: #Fatal alert:
                            self._shutdown(False)

                        #Raise the alert as an exception
                        raise TLSRemoteAlert(alert)

                    # TODO fix renegotiation case
                    #If we received a renegotiation attempt...
                    if recordHeader.type == ContentType.handshake:
                        subType = p.get(1)
                        reneg = False
                        if self._client:
                            if subType == HandshakeType.hello_request:
                                reneg = True
                        else:
                            if subType == HandshakeType.client_hello:
                                reneg = True
                        #Send no_renegotiation, then try again
                        if reneg:
                            alertMsg = Alert()
                            alertMsg.create(AlertDescription.no_renegotiation,
                                            AlertLevel.warning)
                            for result in self._sendMsg(alertMsg):
                                yield result
                            continue

                    #Otherwise: this is an unexpected record, but neither an
                    #alert nor renegotiation
                    for result in self._sendError(\
                            AlertDescription.unexpected_message,
                            "received type=%d" % recordHeader.type):
                        yield result

                break

            #Parse based on content_type
            if recordHeader.type == ContentType.change_cipher_spec:
                yield ChangeCipherSpec().parse(p)
            elif recordHeader.type == ContentType.alert:
                yield Alert().parse(p)
            elif recordHeader.type == ContentType.application_data:
                yield ApplicationData().parse(p)
            elif recordHeader.type == ContentType.handshake:
                #Convert secondaryType to tuple, if it isn't already
                if not isinstance(secondaryType, tuple):
                    secondaryType = (secondaryType,)

                #If it's a handshake message, check handshake header
                if recordHeader.ssl2:
                    subType = p.get(1)
                    if subType != HandshakeType.client_hello:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Can only handle SSLv2 ClientHello messages"):
                            yield result
                    if HandshakeType.client_hello not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message):
                            yield result
                    subType = HandshakeType.client_hello
                else:
                    subType = p.get(1)
                    if subType not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Expecting %s, got %s" % (str(secondaryType), subType)):
                            yield result

                #Update handshake hashes
                # self._handshake_md5.update(compat26Str(p.bytes))
                # self._handshake_sha.update(compat26Str(p.bytes))
                # self._handshake_sha256.update(compat26Str(p.bytes))

                #Parse based on handshake type
                if subType == HandshakeType.client_hello:
                    yield ClientHello(recordHeader.ssl2).parse(p)
                elif subType == HandshakeType.server_hello:
                    yield ServerHello().parse(p)
                elif subType == HandshakeType.certificate:
                    yield Certificate(constructorType).parse(p)
                elif subType == HandshakeType.certificate_request:
                    yield CertificateRequest(self.version).parse(p)
                elif subType == HandshakeType.certificate_verify:
                    yield CertificateVerify(self.version).parse(p)
                elif subType == HandshakeType.server_key_exchange:
                    yield ServerKeyExchange(constructorType).parse(p)
                elif subType == HandshakeType.server_hello_done:
                    yield ServerHelloDone().parse(p)
                elif subType == HandshakeType.client_key_exchange:
                    yield ClientKeyExchange(constructorType, \
                                            self.version).parse(p)
                elif subType == HandshakeType.finished:
                    yield Finished(self.version).parse(p)
                elif subType == HandshakeType.next_protocol:
                    yield NextProtocol().parse(p)
                else:
                    raise AssertionError()

        #If an exception was raised by a Parser or Message instance:
        except SyntaxError as e:
            for result in self._sendError(AlertDescription.decode_error,
                                         formatExceptionTrace(e)):
                yield result

    def _getNextRecord(self):
        #Read the next record header
        b = bytearray(0)
        recordHeaderLength = 1
        ssl2 = False
        while 1:
            try:
                s = self.sock.recv(recordHeaderLength-len(b))
            except socket.error as why:
                #TODO what kind of error are these
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    continue
                else:
                    raise

            #If the connection was abruptly closed, raise an error
            if len(s)==0:
                raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b)==1:
                if b[0] in ContentType.all:
                    ssl2 = False
                    recordHeaderLength = 5
                elif b[0] == 128:
                    ssl2 = True
                    recordHeaderLength = 2
                else:
                    raise SyntaxError()
            if len(b) == recordHeaderLength:
                break

        #Parse the record header
        if ssl2:
            r = RecordHeader2().parse(Parser(b))
        else:
            r = RecordHeader3().parse(Parser(b))

        #Check the record header fields
        if r.length > 18432:
            #TODO do we need to send the error message?
            for result in self._sendError(AlertDescription.record_overflow):
                yield result

        #Read the record contents
        b = bytearray(0)
        while 1:
            try:
                s = self.sock.recv(r.length - len(b))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    continue
                else:
                    raise

            #If the connection is closed, raise a socket error
            if len(s)==0:
                    raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b) == r.length:
                break

        #Check the record header fields (2)
        #We do this after reading the contents from the socket, so that
        #if there's an error, we at least don't leave extra bytes in the
        #socket..
        #
        # THIS CHECK HAS NO SECURITY RELEVANCE (?), BUT COULD HURT INTEROP.
        # SO WE LEAVE IT OUT FOR NOW.
        #
        #if self._versionCheck and r.version != self.version:
        #    for result in self._sendError(AlertDescription.protocol_version,
        #            "Version in header field: %s, should be %s" % (str(r.version),
        #                                                       str(self.version))):
        #        yield result

        # Removed decryption sequence
        p = Parser(b)

        #If it doesn't contain handshake messages, we can just return it
        if r.type != ContentType.handshake:
            yield (r, p)
        #If it's an SSLv2 ClientHello, we can return it as well
        elif r.ssl2:
            yield (r, p)
        else:
            #Otherwise, we loop through and add the handshake messages to the
            #handshake buffer
            while 1:
                if p.index == len(b): #If we're at the end
                    if not self._handshakeBuffer:
                        for result in self._sendError(\
                                AlertDescription.decode_error, \
                                "Received empty handshake record"):
                            yield result
                    break
                #There needs to be at least 4 bytes to get a header
                if p.index+4 > len(b):
                    for result in self._sendError(\
                            AlertDescription.decode_error,
                            "A record has a partial handshake message (1)"):
                        yield result
                p.get(1) # skip handshake type
                msgLength = p.get(3)
                if p.index+msgLength > len(b):
                    for result in self._sendError(\
                            AlertDescription.decode_error,
                            "A record has a partial handshake message (2)"):
                        yield result

                handshakePair = (r, b[p.index-4 : p.index+msgLength])
                self._handshakeBuffer.append(handshakePair)
                p.index += msgLength

            #We've moved at least one handshake message into the
            #handshakeBuffer, return the first one
            recordHeader, b = self._handshakeBuffer[0]
            self._handshakeBuffer = self._handshakeBuffer[1:]
            yield (recordHeader, Parser(b))

    def _sendError(self, alertDescription, errorStr=None):
        raise TLSLocalAlert(alert, errorStr)

    def _shutdown(self, resumable):
        self.sock.close()

    def test(self):
        cHello = ClientHello()
        ciphersuite =copy.copy(CipherSuite.all_suites)
        supportedVersions = []

        ver = (3,1)

        pkt = self._clientHelloPacket(ver, ciphersuite)
        self._initSocket()
        try:
            self.sock.send(pkt)
            for result in self._getMsg(ContentType.handshake, HandshakeType.server_hello):
                print result
                continue
            serverHello = result
            # get certificate
            for result in self._getMsg(ContentType.handshake, HandshakeType.certificate, CertificateType.x509):
                print result
                continue
            serverCertificate = result

        except socket.error, msg:
            raise TLSError("[!] Could not connect to target host")

def main():
    conn = SSLConnection(host="google.com",version= (3,1), port = 443)
    conn.test()

if __name__=="__main__":
    main()

