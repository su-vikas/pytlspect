
class TLSConfig:

    def __init__(self,domain, ip, tls_versions, ciphersuites, compression, server_name):
        self.ip = ip
        self.tls_versions = tls_versions
        self.ciphersuites = ciphersuites
        self.compression = compression
        self.domain = domain
        self.server_name = server_name


