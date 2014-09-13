from utils.constants import *
from utils.packetCreator import *
from socket import *
import binascii,sys
from messages import *

rand_client_finished=b"\x16\x03\x04\x00\x28\x49\17\x19\xe4\xb7\x63\x5a\04\x5a\x11\x0b\xeb\xf4\xb1\x8a\x46\x9b\x16\xfb\x38\xfa\xc5\x9b\xdc\x86\x61\x68\xa2\x08\xe2\xe3\x60\xdb\x60\x44\xae\xf0\x1b\x9b\x88"

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
    #host = "192.168.10.136"
    #host = "drive.google.com"
    host = "172.16.178.44"
    port = 443
    version = (3,2)

    pkt = test_clienthello_pkt()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #set timeout for the socket, socket should complete the transaction in this time
    s.settimeout(1.0)

    try: s.connect((host, port))
    except socket.error, msg:
        print "[!] Could not connect to target host: %s" % msg
        s.close()
        sys.exit()

    #TODO send the client hello
    print "%s" %binascii.hexlify(pkt)
    s.send(pkt)
    data = bytearray()

    try: data = s.recv(5000)
    except socket.error, msg:
        print "[!] Could not connect to target host: %s" % msg
        s.close()

    #print "data: %s" %data

    #TLS/SSLv3 Server Hello
    if data[0] == '\x16':   # server hello code
        print "Received server hello \n"
        ccs_pkt = bytearray()
        ccs = ChangeCipherSpec()
        ccs_pkt = ccs.write()
        recordheader = RecordHeader3().create(version, ContentType.change_cipher_spec, len(ccs_pkt))
        ccs_pkt = recordheader.write() + ccs_pkt
        s.send(ccs_pkt)
        #s.send(rand_client_finished)
        try: data = s.recv(5000)
        except socket.timeout:
            print "[!] Socket timed out "
        except socket.error:
            print "[!] Could not connect to target host: "
            s.close()
            sys.exit()
        except:
            print "[!] caught it caught %s" % msg

        print data

        if data[0] == '\x15':
            alert = Alert().parse(data)
            if alert.level == AlertLevel.fatal:
                print "fatal fatal fatal"

    elif data == '\x15':
        print "Recieved server alert \n"

    return data


#TODO test for SSLv2

def test_serverhello():
   data = test_clienthello()
    #server hello code
   if data == '\x16':
       print "Received server hello \n"
       sHello = ServerHello()
       sHello.parse(Parser(data))
       print sHello.cipher_suite

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
            print "Server hello received"

        elif data == '\x15':
            print "Recieved server alert"

            """
            print "%s is supported" % hex(cipher_id)
            c = hex(cipher_id)[2:]
            c = '0000' + c
            print c
            if str(c) in CipherSuite.cipher_suites.keys():
                print "%s is supported" % CipherSuite.cipher_suites[cipher_id]['name']
            """


def main():
    test_clienthello()
    #test_serverhello()
    #test_ciphersuites_supported()




if __name__ == "__main__":
    main()


