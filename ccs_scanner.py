from utils.constants import *
from utils.packetCreator import *

import socket,binascii,sys
from messages import *


def test_clienthello_pkt():
    cHello = ClientHello()
    #print " testing with TLS 1.1 ..."
    version = (3,2)
    session  = bytearray(0)
    cipherSuites = CipherSuite.aes256Suites

    cHello.create(version, getRandomBytes(32),session,cipherSuites)
    p =  bytearray()
    p = cHello.write()
    recordheader = RecordHeader3().create(version, ContentType.handshake,len(p))
    pkt = recordheader.write() + p
    return pkt


def ccs_scan(appid, app, host):
    #print "starting client hello test at google.com..."
    version = (3,2)
    port=443
    pkt = test_clienthello_pkt()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)

    try: s.connect((host, port))
    except socket.error, msg:
        print "%s, %s, %s, %s" %(appid, app, host, 'host_not_found')
        s.close()
        sys.exit()

    #print "%s" %binascii.hexlify(pkt)
    s.send(pkt)
    data = bytearray()

    try: data = s.recv(5000)
    except socket.error, msg:
        print "%s, %s, %s, %s" %(appid, app, host, 'host_not_found')
        s.close()
        sys.exit()

    #TLS/SSLv3 Server Hello
    if len(data) > 0:
        if data[0] == '\x16':   # server hello code
        #print "Received server hello \n"
            ccs_pkt = bytearray()
            ccs = ChangeCipherSpec()
            ccs_pkt = ccs.write()
            recordheader = RecordHeader3().create(version, ContentType.change_cipher_spec, len(ccs_pkt))
            ccs_pkt = recordheader.write() + ccs_pkt
            s.send(ccs_pkt)

            # if we get SSL alert, patched , if not unpatched
            try:
                data = s.recv(3000)
                print "%s, %s, %s, %s" %(appid, app, host, 'good')
                s.close()
            except socket.timeout:
                print "%s, %s, %s, %s" %(appid, app, host, 'vulnerable')
                s.close()

            except socket.error, msg:
                print "[!] %s,%s, %s, %s" % (appid,app, host, msg)
                s.close()
                sys.exit()


            #print data
            """
            if data[0] == '\x15':
                alert = Alert().parse(data)
                if alert.level == AlertLevel.fatal:
                    print "fatal fatal fatal"
            """

        elif data == '\x15':
            print "%s, %s, %s, %s\n" %(appid, app, host,'re-run')

    return data

def main(argv):
    if len(argv) == 1 :
        print "didn't get the host name \n"
    else:
        appid = argv[1].strip()
        app = argv[2].strip()
        host = argv[3].strip()
#        print "%s, %s, %s" %(appid, app, host)
        ccs_scan(appid, app, host)

if __name__ == "__main__":
    main(sys.argv)


