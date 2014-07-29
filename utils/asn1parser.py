# Author: Trevor Perrin
# Patch from Google adding getChildBytes()
#
# See the LICENSE file for legal information regarding use of this file.

"""Class for parsing ASN.1"""
from .compat import *
from .codec import *

#Takes a byte array which has a DER TLV field at its head
#DER ASN.1 notation with TYPE-LENGTH-VALUE format
class ASN1Parser(object):
    def __init__(self, bytes):
        p = Parser(bytes)
        p.get(1) #skip Type

        #Get Length
        self.length = self._getASN1Length(p)

        #Get Value
        self.value = p.getFixBytes(self.length)

    #Assuming this is a sequence...
    def getChild(self, which):
        return ASN1Parser(self.getChildBytes(which))

    def getChildBytes(self, which):
        p = Parser(self.value)
        for x in range(which+1):
            markIndex = p.index
            p.get(1) #skip Type
            length = self._getASN1Length(p)
            #print "cert length", length
            p.getFixBytes(length)
        return p.bytes[markIndex : p.index]

    #Decode the ASN.1 DER length field
    def _getASN1Length(self, p):
        firstLength = p.get(1)
        if firstLength<=127:
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.get(lengthLength)


