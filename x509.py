# Authors:
#   Trevor Perrin
#   Google - parsing subject field
#
# See the LICENSE file for legal information regarding use of this file.

#TODO
# Common names
# Alternative names
# prefix handling
# valid from
# valid until
# key (weak key, debian)
# issuer
# signature algorithm
# extended validation
# revocation information
# revocation status
# Trusted



"""Class representing an X.509 certificate."""

from utils.asn1parser import ASN1Parser
from utils.constants import *
from utils.cryptomath import *
from utils.keyfactory import _createPublicRSAKey
from utils.pem import *
import binascii


class X509(object):
    """This class represents an X.509 certificate.

    @type bytes: L{bytearray} of unsigned bytes
    @ivar bytes: The DER-encoded ASN.1 certificate

    @type publicKey: L{tlslite.utils.rsakey.RSAKey}
    @ivar publicKey: The subject public key from the certificate.

    @type subject: L{bytearray} of unsigned bytes
    @ivar subject: The DER-encoded ASN.1 subject distinguished name.
    """

    def __init__(self):
        self.bytes = bytearray(0)
        self.publicKey = None
        self.subject = None

        #certificate info
        self.version = None
        self.serial_number = None
        self.signature_algorithm = None
        self.issuer = {}
        self.validFrom = None
        self.validityUntil = None
        self.subject = {}
        self.algorithm_identifier = None
        self.key_algorithm = None
        self.pub_key_info = None
        self.key_size = None

    def parse(self, s):
        """Parse a PEM-encoded X.509 certificate.

        @type s: str
        @param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
        certificate wrapped with "-----BEGIN CERTIFICATE-----" and
        "-----END CERTIFICATE-----" tags).
        """

        bytes = dePem(s, "CERTIFICATE")
        self.parseBinary(bytes)
        return self

    def parseBinary(self, bytes):
        """Parse a DER-encoded X.509 certificate.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: A DER-encoded X.509 certificate.
        """

        self.bytes = bytearray(bytes)
        p = ASN1Parser(bytes)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at.
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5

        # serial number of certificate
        self.serial_number = ASN1Parser(tbsCertificateP.getChildBytes(1))
        #print "[+] Serial number: 0x"+b2a_hex(self.serial_number.value)

        #TODO signature algorithm, not workign yet
        sign_algo = ASN1Parser(ASN1Parser(tbsCertificateP.getChildBytes(2)).getChildBytes(0))

        oid = self.ObjectIdentifierDecoder(sign_algo.value, sign_algo.length)
        oid_str = get_oid_str(oid)

        signature_algorithm = oid_str

        for key,value in OIDMap.oid_map.iteritems():
            if key == oid_str:
                self.signature_algorithm = (oid_str, value)
                #print "[+] Signature ALgorithm: ", value

        #get the issuer
        issuer = tbsCertificateP.getChildBytes(3)
        counter = 0
        while 1:
            try:
                field3 = ASN1Parser(issuer).getChild(counter).getChild(0).getChild(0)
                oid = self.ObjectIdentifierDecoder(field3.value, field3.length)
                oid_str = get_oid_str(oid)
                for key,value in OIDMap.oid_map.iteritems():
                    if key == oid_str:
                        self.issuer[value] = ASN1Parser(issuer).getChild(counter).getChild(0).getChild(1).value
                counter +=1
            except:
                break


        #get the validity
        self.validFrom = ASN1Parser(tbsCertificateP.getChildBytes(4)).getChild(0)
        self.validFrom = self.validFrom.value[:6]

        self.validUntil = ASN1Parser(tbsCertificateP.getChildBytes(4)).getChild(1)
        self.validUntil = self.validUntil.value[:6]

        #Get the subject
        # CANT HANDLE IF ANYTHING CHANGES.  HACKING TO PARSE CERT
        subject = tbsCertificateP.getChildBytes(subjectPublicKeyInfoIndex - 1)
        counter = 0
        while 1:
            try:
                field3 = ASN1Parser(subject).getChild(counter).getChild(0).getChild(0)
                oid = self.ObjectIdentifierDecoder(field3.value, field3.length)
                oid_str = get_oid_str(oid)
                for key,value in OIDMap.oid_map.iteritems():
                    if key == oid_str:
                        self.subject[value] = ASN1Parser(subject).getChild(counter).getChild(0).getChild(1).value
                        #print "     [+] ",value,":", ASN1Parser(self.subject).getChild(counter).getChild(0).getChild(1).value
                counter +=1
            except:
                break

        #Get the subjectPublicKeyInfo
        # sequence -> sequence -> object_identifier
        subjectPublicKeyInfoP = tbsCertificateP.getChild(subjectPublicKeyInfoIndex)
        algorithmP = ASN1Parser(subjectPublicKeyInfoP.getChildBytes(0)).getChild(0)
        algoOID = self.ObjectIdentifierDecoder(algorithmP.value, algorithmP.length)
        algoOID_str = get_oid_str(algoOID)

        for key,value in OIDMap.oid_map.iteritems():
            if key == algoOID_str:
                self.key_algorithm = (algoOID_str, value)

        #Get the subjectPublicKey
        subjectPublicKeyP = subjectPublicKeyInfoP.getChild(1)

        #Adjust for BIT STRING encapsulation
        if self.key_algorithm is not None and self.key_algorithm[1] == 'RSA':
            if (subjectPublicKeyP.value[0] !=0):
                raise SyntaxError()
            subjectPublicKeyP = ASN1Parser(subjectPublicKeyP.value[1:])

            #Get the modulus and exponent
            modulusP = subjectPublicKeyP.getChild(0)
            publicExponentP = subjectPublicKeyP.getChild(1)

            #Decode them into numbers
            # Info: typecasting to long, to debian giving typerror of expecting long, not int

            n = long(bytesToNumber(modulusP.value))
            e = long(bytesToNumber(publicExponentP.value))

            #Create a public key instance
            self.publicKey = _createPublicRSAKey(n, e)
            self.key_size = len(self.publicKey)
            #print "[+] Key Size: ",len(self.publicKey) ,"\n"

        #TODO calculate EC KEY SIZE
        # helped in solving this issue :https://crypto.stackexchange.com/questions/6843/how-do-i-unpack-the-x-and-y-values-from-the-bitstring-in-a-der-ecdsa-public-key
        if self.key_algorithm is not None and self.key_algorithm[1] == 'EC':
            if (subjectPublicKeyP.value[0] !=0):
                raise SyntaxError()

            #uncompressed key, then the following bytes are x and y
            if (subjectPublicKeyP.value[1] ==0x04):
                key_len_byte = len(subjectPublicKeyP.value[2:])
                self.key_size = (key_len_byte/2 )  * 8

            # TODO not sure, probably correct implementation: https://stackoverflow.com/questions/16576434/cryptopp-compressed-ec-keys
            if (subjectPublicKeyP.value[1] ==0x03) or (subjectPublicKeyP.value[1] ==0x02) :
                key_len_byte = len(subjectPublicKeyP.value[2:])
                self.key_size = (key_len_byte)  * 8


    def getFingerprint(self):
        """Get the hex-encoded fingerprint of this certificate.

        @rtype: str
        @return: A hex-encoded fingerprint.
        """
        return b2a_hex(SHA1(self.bytes))

    def writeBytes(self):
        return self.bytes

    def ObjectIdentifierDecoder(self, value, length):
        oid = ()
        index = 1

        # for 1st byte
        first_byte = value[0]
        if 0 <= first_byte <= 39:
            oid = (0,) + oid
        elif 40 <= first_byte <= 79:
            oid = (1, first_byte-40) + oid[1:]
        elif first_byte >= 80:
            oid = (2, first_byte-80) + oid[1:]
        else:
            print "error, panga with 1st byte"

        while index < length:
            subId = value[index]
            index += 1
            if subId < 128:
                oid = oid + (subId,)
            elif subId>128:
                nextSubId = subId
                subId = 0
                while nextSubId >=128:
                    subId = (subId << 7) + (nextSubId & 0x7F)
                    if index >= length:
                        print "error, panga"
                    nextSubId =value[index]
                    index += 1
                oid = oid + ((subId<<7)+nextSubId,)
            elif subId == 128:
                # ASN.1 spec forbids leading zeros (0x80) in OID
                # encoding, tolerating it opens a vulnerability. See
                # http://www.cosic.esat.kuleuven.be/publications/article-1432.pdf
                # page 7
                print "error, panga"
        return oid

    def print_cert(self):
        print "[+] Serial Number: 0x"+b2a_hex(self.serial_number.value)
        print "[+] Signature Algorithm: ", self.signature_algorithm[1]
        print "[+] Issuer"
        for key,value in self.issuer.iteritems():
            print "     [+] "+key+": "+ str(value)

        print "[+] Valid From:" , self.validFrom
        print "[+] Valid Until: ", self.validUntil

        print "[+] Subject:"
        for key, value in self.subject.iteritems():
            print "     [+] "+key+": "+ value

        print "[+] Key Size: " + self.key_algorithm[1] + " "+ str(self.key_size) + " bits"
        print "[+] SHA1 Fingerprint: ", self.getFingerprint()
        print "\n"

def get_oid_str(oid_tuple):
    oid_str = ""
    for elem in oid_tuple:
        oid_str = oid_str + str(elem) + '.'

    oid_str_len = len(oid_str) - 1
    oid_str = oid_str[0:oid_str_len]

    return oid_str
