class Writer(object):
    def __init__(self):
        self.bytes = bytearray(0)

    def add(self, x, length):
        self.bytes += bytearray(length)
        newIndex = len(self.bytes) - 1
        for count in range(length):
            self.bytes[newIndex] = x & 0xFF
            x >>= 8
            newIndex -= 1

    def addFixSeq(self, seq, length):
        for e in seq:
            self.add(e, length)

    def addVarSeq(self, seq, length, lengthLength):
        self.add(len(seq)*length, lengthLength)
        for e in seq:
            self.add(e, length)

