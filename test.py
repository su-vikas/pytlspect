from utils.constants import *
from utils.packetCreator import *

import socket,binascii
from messages import *

def test_clienthello():
    print "starting client hello test..."
    host = "74.125.239.142"
    port = 443
    cHello = ClientHello()
    print " testing with TLS 1.1 ..."
    version = (3,2)
    session  = bytearray(0)

    cipherSuites = CipherSuite.aes256Suites

    cHello.create(version, getRandomBytes(32),session,cipherSuites)

    p =  bytearray()
    p = cHello.write()

    recordheader = RecordHeader3().create(version, ContentType.handshake,len(p))
    pkt = recordheader.write() + p

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try: s.connect((host, port))
    except socket.error, msg:
        print "[!] Could not connect to target host: %s" % msg
        s.close()
        sys.exit()

    #TODO send the client hello
    print "%s" %binascii.hexlify(pkt)
    s.send(pkt)

    try: data = s.recv(1)
    except socket.error, msg:
        print "[!] Could not connect to target host: %s" % msg
        s.close()

    print "data: %s" %data

    #TLS/SSLv3 Server Hello
    if data == '\x16':   # server hello code
        print "Received server hello \n"
    elif data == '\x15':
        print "Recieved server alert \n"

#TODO test for SSLv2

if __name__ == "__main__":
    main()


