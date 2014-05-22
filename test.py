from utils.constants import *
from utils.packetCreator import *

import socket,binascii,sys
from messages import *

def test_clienthello_pkt():
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
    return pkt

def test_clienthello():
    print "starting client hello test at google.com..."
    host = "74.125.239.142"
    port = 443
    pkt = test_clienthello_pkt()
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

    return data


#TODO test for SSLv2

def test_serverhello():
   data = test_clienthello()
    #server hello code
   if data == '\x16':
       print "Received server hello \n"
   elif data == '\x15':
       print "Recieved server alert \n"


def test_ciphersuites_supported():
    host = "74.125.239.142"
    port = 443
    cHello = ClientHello()
    print " testing with TLS 1.1 ..."
    version = (3,2)
    session  = bytearray(0)
    for cipher_id in CipherSuite.all_suites:
        cipher = []
        cipher.append(cipher_id)
        cHello.create(version, getRandomBytes(32),session,cipher)

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
        s.send(pkt)

        try: data = s.recv(1)
        except socket.error, msg:
            print "[!] Could not connect to target host: %s" % msg
            s.close()


        #TLS/SSLv3 Server Hello
        if data == '\x16':   # server hello code
            print "%s is supported" % hex(cipher_id)
            c = hex(cipher_id)[2:]
            c = '0000' + c
            print c
            if str(c) in CipherSuite.cipher_suites.keys():
                print "%s is supported" % CipherSuite.cipher_suites[cipher_id]['name']

        elif data == '\x15':
            print "Recieved server alert"




def main():
    test_ciphersuites_supported()




if __name__ == "__main__":
    main()


