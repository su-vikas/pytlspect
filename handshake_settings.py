class HandshakeSettings(object):
    """
        Encapsulates various parameters that can be used with a TLS handshake.
    """
    def __init__(self, host):
        # connection settings
        self.host = host
        self.port = 443
        self.timeout = 5.0

        # TLS Settings
        self.minKeySize = 1023
        self.maxKeySize = 8193
        self.cipherSuites = None
        self.certificateTypes = None
        self.version = (3,0)

        # TLS Extensions
        self.tack               = True
        self.supports_npn       = True
        self.heartbeat          = True
        self.ocsp               = True
        self.session_ticket     = True
        self.elliptic_curves    = True
        self.ec_point_formats   = True
