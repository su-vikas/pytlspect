#! /usr/bin/env python

# Author: Vikas Gupta
# See the LICENSE file for legal information regarding use of this file.

import sys, os
import time
import argparse
from result import Result
from utils.constants import *
from operator import itemgetter
from ssl_connection import SSLConnection
from errors import *
from cert_checker import CertChecker

class TLSpect:
    def __init__(self, version = (3,2), port = 443, IP = None, host = None, socketTimeout = 5.0):
        self.resultObj = Result(host=host, IP=IP)       # object containing result for present scan
        self.socketTimeout = socketTimeout
        self.host = host
        self.port = port
        self.version = version
        self.conn = SSLConnection(host = self.host,version= self.version, port = self.port, timeout = self.socketTimeout)

    def getIP(self):
        """ Get the IP of the host being scanned"""
        self.resultObj.IP = self.conn.getIP()
        self.resultObj.printIP()

    def enumerateSSLVersion(self):
        """ Get the list of all SSL versions supported"""
        sslVersions = self.conn.enumerateSSLVersions()
        self.resultObj.sslVersions = sslVersions
        self.resultObj.maxSSLVersion = max(sslVersions, key=itemgetter(1))
        self.resultObj.printSSLVersions()

    def enumerateCiphers(self):
        """ Get the list of ciphers supported for various versions in default order"""
        for s in self.resultObj.sslVersions:
            cipherSuitesDetected = self.conn.enumerateCiphers(s)

            cipherSuitesName = []
            for cipher_id in cipherSuitesDetected:
                cipherSuitesName.append(CipherSuite.cipher_suites[cipher_id]['name'])
            self.resultObj.updateCiphers(s, cipherSuitesName)
                #print "         " + CipherSuite.cipher_suites[cipher_id]['name']

        self.resultObj.printCipherSuites()
        print "\n[+] LIST OF POTENTIALLY WEAK CIPHERS:"
        for cipher_id in cipherSuitesDetected:
            if 'RC4' in CipherSuite.cipher_suites[cipher_id]['enc']:
                print "     "+CipherSuite.cipher_suites[cipher_id]['name']

    def isCompression(self):
        """ Check if the compression is supported """
        self.resultObj.isCompression = self.conn.isCompressionSupported()
        self.resultObj.printCompression()

    def certificateTest(self):
        """ extract the certificate chain information """
        certificate_chain = self.conn.scanCertificates(self.version)
        checker = CertChecker(self.host, certificate_chain)
        checker.checkExpiryDate()

        self.resultObj.certChain = certificate_chain
        self.resultObj.printCertificates()


    def extensionTest(self):
        self.conn.supportedExtensions()

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

        #time.sleep(3)
        ##make connection with SSLv3.0, i.e emulate downgrade situation with TLS_FALLBACK_SCSV ciphersuite
        #version = (3,0)
        #conn = SSLConnection(host, version, 443, 5.0)
        #conn.doClientHello(host, version)
        #should give an alert now

    def printResults(self):
        print self.resultObj


def parse_args():
    """ parse the commandline args """
    parser = argparse.ArgumentParser(description="Scan for various TLS configurations")
    parser.add_argument("-d", "--domain", required=True, help="The hostname to be scanned for", dest="host")
    parser.add_argument("-p", "--port", help="Port number to scan at, defaults to 443", dest="port")
    parser.add_argument("-a", "--all", help="Scan for all parameters", action="store_true", default=False, dest="all_param_switch")
    parser.add_argument("-v", "--version", default=(3,2), help="SSL version to scan for", dest="version")

    parser.add_argument("-c","--ciphers", help="Scan only for ciphers supported", action="store_true", default=False,dest="ciphers")
    parser.add_argument("-z","--compression", help="Scan only for if compression supported", action="store_true", default=False, dest="compress")
    parser.add_argument("-t","--tls-versions", help="Scan only for supported TLS versions", action="store_true", default=False, dest="tls_versions")
    parser.add_argument("-w", "--weak-ciphers", help="Report potentially weak ciphers only", action="store_true", default=False, dest="weak_ciphers")
    parser.add_argument("-C", "--cert", help="Show certificate details", action="store_true", default=False,dest="cert_detail")
    parser.add_argument("-s", "--cert-chain", help="Show certificate chain details", action="store_true", default=False, dest="cert_chain")
    parser.add_argument("-e", "--tls-ext", help="Show supported TLS extensions", action="store_true", default=False, dest="tls_ext")
    parser.add_argument("-P", "--poodle", help="Test for Poodle SSL attack", action="store_true", default=False,dest='poodle_switch')
    parser.add_argument("-H", "--heartbleed", help="Test for Heartbled SSL vulnerability", action="store_true", default=False, dest='heartbleed_switch')

    results = parser.parse_args()

    # scan for TLS parameters
    tlspect = None
    if results.host:
        if results.port:
            tlspect = TLSpect(host = results.host, port = results.port)
        else:
            tlspect = TLSpect(host = results.host)

    if results.all_param_switch:
        tlspect.getIP()
        tlspect.enumerateSSLVersion()
        tlspect.enumerateCiphers()
        tlspect.isCompression()
        tlspect.certificateTest()
        tlspect.extensionTest()


    if results.ciphers:
        tlspect.enumerateSSLVersion()
        tlspect.enumerateCiphers()

    if results.tls_versions:
        tlspect.enumerateSSLVersion()

    if results.compress:
        tlspect.isCompression()

    if results.weak_ciphers:
        pass

    if results.cert_chain or results.cert_detail:
        tlspect.certificateTest()

    if results.poodle_switch:
        poodleTest(host, version)


def main(argv):
    parse_args()

if __name__ == "__main__":
    main(sys.argv)






