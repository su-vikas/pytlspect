#! /usr/bin/env python

# Author: Vikas Gupta
# See the LICENSE file for legal information regarding use of this file.

import sys, os
import time
import argparse
from utils.constants import *
from operator import itemgetter
from ssl_connection import SSLConnection
from errors import *

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
    print "\n[+] CIPHERS SUPPORTED IN DEFAULT PREFERRED ORDER:"
    for s in sslVersions:
        print "\n     [+] TLS Version:", s
        #get the ciphers supported
        cipherSuitesDetected = conn.enumerateCiphers(s)
        for cipher_id in cipherSuitesDetected:
            print "         " + CipherSuite.cipher_suites[cipher_id]['name']

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
    #tls_config = TLSConfig(domain = host,ip= conn.getIP(), tls_versions = sslVersions, ciphersuites = cipherSuitesDetected, compression = compression)
    #treturn tls_config


def certificateTest(host, version):
    version=(3,2)
    connection_obj = SSLConnection(host,version,443,5.0)
    print "[*] CERTIFICATE CHAIN"
    connection_obj.scanCertificates(host, version)

def extensionTest(host, version):
    version=(3,2)
    connection_obj = SSLConnection(host,version,443,5.0)
    connection_obj.supportedExtensions()

def print_scan_result():
    pass


def poodleTest(host, version):
    """
     make a connection with TLS1.0, drop it
     make another connection with SSLv3 and containing TLS_FALLBACK_SCSV ciphersuite in clienthello.
     if alert (inapproprite_fallback(86) is returned, server is GOOD, not poodle susceptible)
     if no alert server is susceptible to POODLE.
     REF: http://www.exploresecurity.com/poodle-and-the-tls_fallback_scsv-remedy/
    """
    # make connection with TLS1.0
    try:
        version = (3,0)
        conn = SSLConnection(host, version, 443, 5.0)
        value = conn.doClientHello(host, version)
        if value is "Alert":
            print "False"
        elif value is "Supported":
            print "True"

        #print "[+] IP:", conn.getIP(), " \n"
    except Exception, err:
        print "Error"

"""
    time.sleep(3)
    #make connection with SSLv3.0, i.e emulate downgrade situation with TLS_FALLBACK_SCSV ciphersuite
    version = (3,0)
    conn = SSLConnection(host, version, 443, 5.0)
    conn.doClientHello(host, version)
    """
    #should give an alert now

# parse commandline args
def parse_args():
    parser = argparse.ArgumentParser(description="Scan for various TLS configurations")
    parser.add_argument("-d", "--domain", required=True, help="The hostname to be scanned for")
    parser.add_argument("-p", "--port", help="Port number to scan at, defaults to 443")
    parser.add_argument("-a", "--all", help="Scan for all parameters")
    parser.add_argument("-v", "--version", default=(3,2), help="Scan for all parameters")

    parser.add_argument("-c","--ciphers", help="Scan only for ciphers supported" )
    parser.add_argument("-t","--tls-versions", help="Scan only for supported TLS versions")
    parser.add_argument("-w", "--weak-ciphers", help="Report potentially weak ciphers only")
    parser.add_argument("-C", "--cert", help="Show certificate details")
    parser.add_argument("-s", "--cert-chain", help="Show certificate chain details")
    parser.add_argument("-e", "--tls-ext", help="Show supported TLS extensions")
    parser.add_argument("-P", "--poodle", help="Test for Poodle SSL attack", action="store_true", default=False,dest='poodle_switch')



#TODO fix the issue below with arg parsing
    results = parser.parse_args()
    args = vars(parser.parse_args())
    host = args['domain']
    port = args['port']
    version = args['version']
    all_param = args['all']

    if results.poodle_switch:
    # test for poodle.
        poodleTest(host, version)
    else:
        cipherTest(host,version)
        cert = certificateTest(host, version)
        extensionTest(host, version)



def main(argv):
    parse_args()

if __name__ == "__main__":
    main(sys.argv)






