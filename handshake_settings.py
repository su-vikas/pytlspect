class HandshakeSettings(object):
    """
        Encapsulates various parameters that can be used with a TLS handshake.
    """
    def __init__(self):
        self.minKeySize = 1023
        self.maxKeySize = 8193
        self.cipherSuites = None
        self.certificateTypes = None
        self.minVersion = (3,0)
        self.maxVersion = (3,3)


