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
        self.issuer = None
        self.validFrom = None
        self.validityUntil = None
        self.subject = None
        self.pub_key_info = None

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
        print "serial number", b2a_hex(self.serial_number.value)


        #TODO signature algorithm, not workign yet
        self.signature_algorithm = ASN1Parser(ASN1Parser(tbsCertificateP.getChildBytes(2)).getChildBytes(0))

        oid = self.ObjectIdentifierDecoder(self.signature_algorithm.value, self.signature_algorithm.length)
        print oid
        for key,value in OIDMap.oid_map.iteritems():
            if key == oid:
                print value

        #get the issuer
        self.issuer = ASN1Parser(tbsCertificateP.getChildBytes(3))
        print "issuer", self.issuer.value


        #get the validity
        self.validFrom = ASN1Parser(tbsCertificateP.getChildBytes(4)).getChild(0)
        print "valid from", self.validFrom.value

        self.validUntil = ASN1Parser(tbsCertificateP.getChildBytes(4)).getChild(1)
        print "valid until", self.validUntil.value

        #Get the subject
        self.subject = tbsCertificateP.getChildBytes(subjectPublicKeyInfoIndex - 1)
        print "subject", self.subject, "\n"

        #Get the subjectPublicKeyInfo
        subjectPublicKeyInfoP = tbsCertificateP.getChild(subjectPublicKeyInfoIndex)

        #Get the algorithm
        algorithmP = subjectPublicKeyInfoP.getChild(0)
        rsaOID = algorithmP.value
        if list(rsaOID) != [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]:
            raise SyntaxError("Unrecognized AlgorithmIdentifier")

        #Get the subjectPublicKey
        subjectPublicKeyP = subjectPublicKeyInfoP.getChild(1)

        #Adjust for BIT STRING encapsulation
        if (subjectPublicKeyP.value[0] !=0):
            raise SyntaxError()
        subjectPublicKeyP = ASN1Parser(subjectPublicKeyP.value[1:])

        #Get the modulus and exponent
        modulusP = subjectPublicKeyP.getChild(0)
        publicExponentP = subjectPublicKeyP.getChild(1)

        #Decode them into numbers
        n = bytesToNumber(modulusP.value)
        e = bytesToNumber(publicExponentP.value)

        #Create a public key instance
        self.publicKey = _createPublicRSAKey(n, e)

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

