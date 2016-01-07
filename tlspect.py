'''
# =============================================================================
#      FileName: tlsspect.py
#          Desc:
#        Author: Vikas Gupta
#         Email: vikasgupta.nit@gmail.com
#      HomePage:
#       Version: 0.0.1
#    LastChange: 2016-01-07 18:54:48
#       History:
# =============================================================================
'''
import sys
import os
import copy
import time
import csv
import argparse
from operator import itemgetter

from handshake_settings import HandshakeSettings
from ssl_connection import SSLConnection
from utils.constants import SSLVersions, CipherSuite
from cert_checker import CertChecker
from result import Result
from errors import *

class TLSpect(object):
    """
        Encapsulates all the scans that can be performed against a server.
    """

    def __init__(self, host, port=443):
        self.settings = HandshakeSettings(host)
        self.settings.port = port
        self.result = Result()

        self.isCertificate = False     # to maintain state if certificates has been parsed.

    def startHandshake(self, settings):
        """
            Checks if the sslv3 supported by the remote server.
        """
        connection = SSLConnection(settings)
        result = connection.startHandshake(settings)
        return result

    def _parseExtensions(self, serverHello):
        extensions = {}
        if serverHello.next_protos:
            extensions['next_protocol_negotiation'] = [e for e in serverHello.next_protos]
        if serverHello.server_name:
            extensions['server_name'] = True
        if serverHello.tackExt:
            extensions['tack'] = True
        if serverHello.renegotiation_info:
            extensions['renegotiation_info'] = True
        if serverHello.heartbeat:
            extensions['Heartbeat'] = True
        if serverHello.ocsp:
            extensions['status_request'] = True
        if serverHello.session_ticket:
            extensions['SessionTicket TLS'] = True
        if serverHello.ec_point_formats:
            extensions['ec_point_formats'] = True

        return extensions

    def _parseCertificate(self, serverCertificate):

        if not self.isCertificate:
            checker = CertChecker(self.settings.host, serverCertificate)
            checker.checkExpiryDate()
            self.result.certChain = serverCertificate

            self.isCertificate = True

    def getSSLV3Params(self):
        """
            Gets all the parameters for SSLv3.
        """
        self.settings.version = SSLVersions.SSLV3
        try:
            result = self.startHandshake(self.settings)
            if result:
                serverHello, serverCertificate = result
                self.result.isCompressionSSLV3 = serverHello.compression_method
                if self.settings.version == serverHello.server_version:
                    self.result.isSSLV3 = True

                self.result.extensionsSSLV3 = self._parseExtensions(serverHello)

                self._parseCertificate(serverCertificate)
        except TLSRemoteAlert:
            #TODO add logging.
            pass

    def getTLSV10Params(self):
        """
            Gets all the parameters for SSLv3.
        """
        self.settings.version = SSLVersions.TLSV10
        try:
            result = self.startHandshake(self.settings)
            if result:
                serverHello, serverCertificate = result
                self.result.isCompressionTLSV10 = serverHello.compression_method
                if self.settings.version == serverHello.server_version:
                    self.result.isTLSV10 = True

                self.result.extensionsTLSV10 = self._parseExtensions(serverHello)
                self._parseCertificate(serverCertificate)

        except TLSRemoteAlert:
            pass

    def getTLSV11Params(self):
        """
        """
        self.settings.version = SSLVersions.TLSV11
        try:
            result = self.startHandshake(self.settings)
            if result:
                serverHello, serverCertificate = result
                self.result.isCompressionTLSV11 = serverHello.compression_method
                if self.settings.version == serverHello.server_version:
                    self.result.isTLSV11 = True

                self.result.extensionsTLSV11 = self._parseExtensions(serverHello)
                self._parseCertificate(serverCertificate)
        except TLSRemoteAlert:
            pass

    def getTLSV12Params(self):
        self.settings.version = SSLVersions.TLSV12
        try:
            result = self.startHandshake(self.settings)
            if result:
                serverHello, serverCertificate = result
                self.result.isCompressionTLSV12 = serverHello.compression_method
                if self.settings.version == serverHello.server_version:
                    self.result.isTLSV12 = True

                self.result.extensionsTLSV12 = self._parseExtensions(serverHello)
                self._parseCertificate(serverCertificate)
        except TLSRemoteAlert:
            pass

    def getAllParams(self):
        self.getSSLV3Params()
        self.getTLSV10Params()
        self.getTLSV11Params()
        self.getTLSV12Params()

    def getIP(self):
        addr = socket.gethostbyname(self.settings.host)
        self.ip = addr
        return self.ip

    def getIPs(self):
        addr = socket.gethostbyname(self.host)
        self.ip = addr
        return self.ip

    def poodleSSL(self):
        """
        make a connection with TLS1.0, drop it
        make another connection with SSLv3 and containing TLS_FALLBACK_SCSV ciphersuite in clienthello.
        if alert (inapproprite_fallback(86) is returned, server is GOOD, not poodle susceptible)
        if no alert server is susceptible to POODLE.
        REF: http://www.exploresecurity.com/poodle-and-the-tls_fallback_scsv-remedy/
        """
        # make connection with TLS1.0
        try:
            self.settings.version = SSLVersions.SSLV3
            self.settings.cipherSuites = CipherSuite.poodleTestSuites
            result = self.startHandshake(self.settings)
            self.result.isPoodle = True

        except TLSRemoteAlert as err:
            if err.description == 86:
                self.result.isPoodle = False

    def poodleTLS(self):
        pass

    def freakTest(self, result):
        """
        The attack involves use EXPORT_RSA which either uses 512 bits or 1024 bits RSA keys.
        FOr the test, we will check if EXPORT_RSA is enabled for a server or not.
        @param result: to return the result in case of multiprocessing module
        """
        try:
            # determine ssl versions
            self.enumerateSSLVersion()

            # run scans for all versions
            cipherSuite = copy.copy(CipherSuite.freakTestSuites)
            for s in self.resultObj.sslVersions:
                cipherSuitesDetected = self.conn.enumerateCiphers(version = s, customCipherSuite = cipherSuite)

                cipherSuitesName = []
                for cipher_id in cipherSuitesDetected:
                    cipherSuitesName.append(CipherSuite.cipher_suites[cipher_id]['name'])
                self.resultObj.updateCiphers(s, cipherSuitesName)

                if cipherSuitesName:
                    result = "True"
                    return "True"

                else:
                    result = "False"
                    return "False"
                #print "         " + CipherSuite.cipher_suites[cipher_id]['name']

            # self.resultObj.printCipherSuites()
            # if export rsa supported, website is vulnerable

        except Exception as err:
            print err
            results="False"
            return "False"

    def logjamTest(self, result):
        """
        The attack involves use DHE_EXPORT which either uses 512 bits keys.
        FOr the test, we will check if DHE_EXPORT is enabled for a server or not.
        @param result: to return the result in case of multiprocessing module
        """
        try:
            # determine ssl versions
            self.enumerateSSLVersion()

            # run scans for all versions
            cipherSuite = copy.copy(CipherSuite.logjamTestSuites)
            for s in self.resultObj.sslVersions:
                cipherSuitesDetected = self.conn.enumerateCiphers(version = s, customCipherSuite = cipherSuite)

                cipherSuitesName = []
                for cipher_id in cipherSuitesDetected:
                    cipherSuitesName.append(CipherSuite.cipher_suites[cipher_id]['name'])
                    self.resultObj.updateCiphers(s, cipherSuitesName)

                if cipherSuitesName:
                    result = "True"
                    return "True"

                else:
                    result = "False"
                    return "False"
                #print "         " + CipherSuite.cipher_suites[cipher_id]['name']

            # self.resultObj.printCipherSuites()
            # if export rsa supported, website is vulnerable

        except Exception as err:
            print err
            results="False"
            return "False"

    def openSSLCCS(self):
        pass

    def heartbleed(self):
        pass


def parse_args():
    """ parse the commandline args """
    parser = argparse.ArgumentParser(description="Scan for various TLS configurations")
    parser.add_argument("-d", "--domain", required=True, help="The hostname to be scanned for", dest="host")
    parser.add_argument("-p", "--port", help="Port number to scan at, defaults to 443", dest="port")
    parser.add_argument("-a", "--all", help="Scan for all parameters", action="store_true", default=False, dest="all_param_switch")
    # parser.add_argument("-v", "--version", default=(3,2), help="SSL version to scan for", dest="version")

    # parser.add_argument("-i","--ips", help="Scan for all IPs", action="store_true", default=False, dest="ips")
    # parser.add_argument("-c","--ciphers", help="Scan only for ciphers supported", action="store_true", default=False,dest="ciphers")
    # parser.add_argument("-z","--compression", help="Scan only for if compression supported", action="store_true", default=False, dest="compress")
    # parser.add_argument("-t","--tls-versions", help="Scan only for supported TLS versions", action="store_true", default=False, dest="tls_versions")
    # parser.add_argument("-w", "--weak-ciphers", help="Report potentially weak ciphers only", action="store_true", default=False, dest="weak_ciphers")
    # parser.add_argument("-C", "--cert", help="Show certificate details", action="store_true", default=False,dest="cert_detail")
    # parser.add_argument("-s", "--cert-chain", help="Show certificate chain details", action="store_true", default=False, dest="cert_chain")
    # parser.add_argument("-e", "--tls-ext", help="Show supported TLS extensions", action="store_true", default=False, dest="tls_ext")
    # Follow rule of having caps for vulnerabilities.
    parser.add_argument("-P", "--poodle", help="Test for POODLE SSL attack", action="store_true", default=False,dest='poodle_switch')
    parser.add_argument("-H", "--heartbleed", help="Test for Heartbled SSL vulnerability", action="store_true", default=False, dest='heartbleed_switch')
    parser.add_argument("-F", "--freak", help="Test for FREAK SSL vulnerability", action="store_true", default=False, dest='freak_switch')
    parser.add_argument("-L", "--logjam", help="Test for LOGJAM SSL vulnerability", action="store_true", default=False, dest='logjam_switch')


    results = parser.parse_args()

    # scan for TLS parameters
    tlspect = None
    if results.host:
        if results.port:
            tlspect = TLSpect(host = results.host, port = results.port)
        else:
            tlspect = TLSpect(host = results.host)

    # CHeck for all TLS Params
    if results.all_param_switch:
        tlspect.getAllParams()
        tlspect.getIP()
        tlspect.result.output()


    """
    # Check for TLS ciphers
    if results.ciphers:
        tlspect.enumerateSSLVersion()
        tlspect.enumerateCiphers()

    # Check for TLS versions supported
    if results.tls_versions:
        tlspect.enumerateSSLVersion()

    # Check for compression
    if results.compress:
        tlspect.isCompression()

    # TODO
    if results.weak_ciphers:
        pass

    # check for certificate chain
    if results.cert_chain or results.cert_detail:
        tlspect.certificateTest()
    """

    # check for poodle
    if results.poodle_switch:
        poodleTest(host, version)

    # check for freak
    if results.freak_switch:
        result = None
        print tlspect.freakTest(result)

    # check for logjam
    if results.logjam_switch:
        result = None
        print tlspect.logjamTest(result)


def main():
    parse_args()

if __name__ == "__main__":
    main()

