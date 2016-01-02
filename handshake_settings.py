class HandshakeSettings(object):
    """
        Encapsulates various parameters that can be used with a TLS handshake.
    """
    def __init__(self):
        self.min_key_size = 1023
        self.max_key_size = 8193
        self.cipher_suites = None
        self.certificate_types = None
        self.min_version = (3,0)
        self.max_version = (3,3)


