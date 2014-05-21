import socket,sys,os


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


class Connection(object):
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
    def client_hello(self, host, port):
        ssl_client_hello = '\x16\x03\x01'
        \x01





