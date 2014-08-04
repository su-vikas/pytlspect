# Authors:
#   Trevor Perrin
#   Google - defining ClientCertificateType
#   Google (adapted by Sam Rushing) - NPN support
#   Dimitris Moraitis - Anon ciphersuites
#   Dave Baggett (Arcode Corporation) - canonicalCipherName
#
# See the LICENSE file for legal information regarding use of this file.

"""Constants used in various places."""

class CertificateType:
    x509 = 0
    openpgp = 1

class ClientCertificateType:
    rsa_sign = 1
    dss_sign = 2
    rsa_fixed_dh = 3
    dss_fixed_dh = 4

class HandshakeType:
    hello_request = 0
    client_hello = 1
    server_hello = 2
    certificate = 11
    server_key_exchange = 12
    certificate_request = 13
    server_hello_done = 14
    certificate_verify = 15
    client_key_exchange = 16
    finished = 20
    next_protocol = 67

class ContentType:
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    all = (20,21,22,23)

class ExtensionType:    # RFC 6066 / 4366
    server_name = 0     # RFC 6066 / 4366
    srp = 12            # RFC 5054
    cert_type = 9       # RFC 6091
    tack = 0xF300
    supports_npn = 13172
    renegotiation_info = 0xFF01
    heartbeat = 0x000F

class NameType:
    host_name = 0

class AlertLevel:
    warning = 1
    fatal = 2

class AlertDescription:
    """
    @cvar bad_record_mac: A TLS record failed to decrypt properly.

    If this occurs during a SRP handshake it most likely
    indicates a bad password.  It may also indicate an implementation
    error, or some tampering with the data in transit.

    This alert will be signalled by the server if the SRP password is bad.  It
    may also be signalled by the server if the SRP username is unknown to the
    server, but it doesn't wish to reveal that fact.


    @cvar handshake_failure: A problem occurred while handshaking.

    This typically indicates a lack of common ciphersuites between client and
    server, or some other disagreement (about SRP parameters or key sizes,
    for example).

    @cvar protocol_version: The other party's SSL/TLS version was unacceptable.

    This indicates that the client and server couldn't agree on which version
    of SSL or TLS to use.

    @cvar user_canceled: The handshake is being cancelled for some reason.

    """

    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed = 21
    record_overflow = 22
    decompression_failure = 30
    handshake_failure = 40
    no_certificate = 41 #SSLv3
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    export_restriction = 60
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    user_canceled = 90
    no_renegotiation = 100
    unknown_psk_identity = 115

class OIDMap:
    # taken from https://github.com/hiviah/pyx509/tree/master/pkcs7/asn1_models
    '''
    Map of OIDs and their names
    '''
    oid_map = {
           "1.3.14.3.2.26" : "SHA-1",
           "2.16.840.1.101.3.4.2.1" : "SHA-256",
           "2.16.840.1.101.3.4.2.2" : "SHA-384",
           "2.16.840.1.101.3.4.2.3" : "SHA-512",
           "1.2.840.113549.1.7.1" : "data",
           "1.2.840.113549.1.7.2" : "signedData",
           "1.2.840.113549.1.1.5" : "SHA1withRSA",
           "1.2.840.113549.1.1.1" : "RSA",
           "1.2.840.113549.1.1.11" : "SHA256withRSA",
           "1.2.840.10040.4.1" : "DSA",
           "1.2.840.10040.4.3" : "SHA1withDSA",
           "1.2.840.10045.4.1" : "SHA1withECDSA",
           "1.2.840.10045.2.1" : "EC",


           "2.5.4.6" : "id-at-countryName",
           "2.5.4.8": "id-at-stateorProvinceName",
           "2.5.4.7" : "id-at-localityName",
           "2.5.4.10" : "id-at-organizationName ",
           "2.5.4.3" : "id-at-commonName",
           "2.5.4.11" : "id-at-organizationalUnitName",

           "2.5.29.17" : "id-ce-subjectAltName",
           "2.5.29.19" : "basicConstraints",
           "2.5.29.32" : "Certificate policies",
           "1.3.6.1.5.5.7.1.3" : "id-pe-qcStatements",
           "2.5.29.15" : "id-ce-keyUsage",
           "2.5.29.14" : "id-ce-subjectKeyIdentifier ",
           "2.5.29.31" : "id-ce-CRLDistributionPoints ",
           "2.5.29.35" : "id-ce-authorityKeyIdentifier ",

           "2.5.29.20" : "CRL Number",
           "2.5.29.21" : "Reason Code",
           "2.5.29.24" : "Invalidity Data",


           "1.2.840.113549.1.9.3" : "contentType",
           "1.2.840.113549.1.9.4" : "messageDigest",
           "1.2.840.113549.1.9.5" : "Signing Time"
           }

class AlgorithmIdentifier:
    #https://www.ipa.go.jp/security/rfc/RFC3279EN.html#211
    # sha-1 with rsa encryption: 1.2.840.113549.1.1.5
    shawithrsa = bytearray(b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05')

    #sha256 with rsa encryption
    sha256withrsa = bytearray(b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b')

    # md-5 with rsa encryption: 1.2.840.113549.1.1.4
    md5withrsa = bytearray(b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04')

    # md-2 with rsa encryption: 1.2.840.113549.1.1.2
    md2withrsa = bytearray(b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02')


    # dsa with sha 1
    # ecdsa with sha1

class CipherSuite:
    # Weird pseudo-ciphersuite from RFC 5746
    # Signals that "secure renegotiation" is supported
    # We actually don't do any renegotiation, but this
    # prevents renegotiation attacks


    # Cipher suite ids and names from wireshark/epan/dissectors/packet-ssl-utils.c + GOST
    # Classification is based OpenSSL's ciphers(1) man page.
    cipher_suites = {
    '000000': {'name': 'TLS_NULL_WITH_NULL_NULL', 'protocol': 'TLS', 'kx': 'NULL', 'au': 'NULL', 'enc': 'NULL', 'bits': '0', 'mac': 'NULL', 'kxau_strength': 'NULL', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '000001': {'name': 'TLS_RSA_WITH_NULL_MD5', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '000002': {'name': 'TLS_RSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '000003': {'name': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT', 'au': 'RSA_EXPORT', 'enc': 'RC4_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000004': {'name': 'TLS_RSA_WITH_RC4_128_MD5', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000005': {'name': 'TLS_RSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000006': {'name': 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT', 'au': 'RSA_EXPORT', 'enc': 'RC2_CBC_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000007': {'name': 'TLS_RSA_WITH_IDEA_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'IDEA_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000008': {'name': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA_EXPORT', 'au': 'RSA_EXPORT', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000009': {'name': 'TLS_RSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '00000A': {'name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00000B': {'name': 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '00000C': {'name': 'TLS_DH_DSS_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '00000D': {'name': 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00000E': {'name': 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '00000F': {'name': 'TLS_DH_RSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '000010': {'name': 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000011': {'name': 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000012': {'name': 'TLS_DHE_DSS_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '000013': {'name': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000014': {'name': 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000015': {'name': 'TLS_DHE_RSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '000016': {'name': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000017': {'name': 'TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'RC4_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'MITM', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000018': {'name': 'TLS_DH_Anon_WITH_RC4_128_MD5', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'MITM', 'enc_strength': 'MEDIUM', 'overall_strength': 'MITM'},
    '000019': {'name': 'TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '00001A': {'name': 'TLS_DH_Anon_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'LOW', 'overall_strength': 'MITM'},
    '00001B': {'name': 'TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00001C': {'name': 'SSL_FORTEZZA_KEA_WITH_NULL_SHA', 'protocol': 'SSL', 'kx': 'FORTEZZA', 'au': 'KEA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00001D': {'name': 'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA', 'protocol': 'SSL', 'kx': 'FORTEZZA', 'au': 'KEA', 'enc': 'FORTEZZA_CBC', 'bits': '80', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00001E': {'name': 'TLS_KRB5_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '00001F': {'name': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000020': {'name': 'TLS_KRB5_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000021': {'name': 'TLS_KRB5_WITH_IDEA_CBC_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'IDEA_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000022': {'name': 'TLS_KRB5_WITH_DES_CBC_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '000023': {'name': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000024': {'name': 'TLS_KRB5_WITH_RC4_128_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000025': {'name': 'TLS_KRB5_WITH_IDEA_CBC_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'IDEA_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000026': {'name': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'DES_CBC_40', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000027': {'name': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC2_CBC_40', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000028': {'name': 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC4_40', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000029': {'name': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'DES_CBC_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '00002A': {'name': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC2_CBC_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '00002B': {'name': 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC4_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '00002C': {'name': 'TLS_PSK_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00002D': {'name': 'TLS_DHE_PSK_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00002E': {'name': 'TLS_RSA_PSK_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00002F': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000030': {'name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000031': {'name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000032': {'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000033': {'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000034': {'name': 'TLS_DH_Anon_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '000035': {'name': 'TLS_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000036': {'name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000037': {'name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000038': {'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000039': {'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00003A': {'name': 'TLS_DH_Anon_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00003B': {'name': 'TLS_RSA_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00003C': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00003D': {'name': 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00003E': {'name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00003F': {'name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000040': {'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000041': {'name': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000042': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000043': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000044': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000045': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000046': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '000047': {'name': 'TLS_ECDH_ECDSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '000048': {'name': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000049': {'name': 'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '00004A': {'name': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00004B': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00004C': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000060': {'name': 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'RC4_56', 'bits': '56', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000061': {'name': 'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'RC2_CBC_56', 'bits': '56', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000062': {'name': 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'LOW', 'overall_strength': 'EXPORT'},
    '000063': {'name': 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '000064': {'name': 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'RC4_56', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000065': {'name': 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'RC4_56', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '000066': {'name': 'TLS_DHE_DSS_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000067': {'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000068': {'name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000069': {'name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00006A': {'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00006B': {'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00006C': {'name': 'TLS_DH_Anon_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00006D': {'name': 'TLS_DH_Anon_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '000080': {'name': 'TLS_GOSTR341094_WITH_28147_CNT_IMIT', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-94', 'au': 'VKO GOST R 34.10-94', 'enc': 'GOST28147', 'bits': '256', 'mac': 'IMIT_GOST28147', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000081': {'name': 'TLS_GOSTR341001_WITH_28147_CNT_IMIT', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-2001', 'au': 'VKO GOST R 34.10-2001', 'enc': 'GOST28147', 'bits': '256', 'mac': 'IMIT_GOST28147', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000082': {'name': 'TLS_GOSTR341094_WITH_NULL_GOSTR3411', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-94 ', 'au': 'VKO GOST R 34.10-94 ', 'enc': 'NULL', 'bits': '0', 'mac': 'HMAC_GOSTR3411', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '000083': {'name': 'TLS_GOSTR341001_WITH_NULL_GOSTR3411', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-2001', 'au': 'VKO GOST R 34.10-2001', 'enc': 'NULL', 'bits': '0', 'mac': 'HMAC_GOSTR3411', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '000084': {'name': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000085': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000086': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000087': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000088': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000089': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00008A': {'name': 'TLS_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00008B': {'name': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00008C': {'name': 'TLS_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00008D': {'name': 'TLS_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00008E': {'name': 'TLS_DHE_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00008F': {'name': 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000090': {'name': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000091': {'name': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000092': {'name': 'TLS_RSA_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '000093': {'name': 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000094': {'name': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000095': {'name': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000096': {'name': 'TLS_RSA_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000097': {'name': 'TLS_DH_DSS_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000098': {'name': 'TLS_DH_RSA_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '000099': {'name': 'TLS_DHE_DSS_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00009A': {'name': 'TLS_DHE_RSA_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00009B': {'name': 'TLS_DH_Anon_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00009C': {'name': 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00009D': {'name': 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00009E': {'name': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00009F': {'name': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A0': {'name': 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A1': {'name': 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A2': {'name': 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A3': {'name': 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A4': {'name': 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A5': {'name': 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A6': {'name': 'TLS_DH_Anon_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A7': {'name': 'TLS_DH_Anon_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '0000A8': {'name': 'TLS_PSK_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000A9': {'name': 'TLS_PSK_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000AA': {'name': 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000AB': {'name': 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000AC': {'name': 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000AD': {'name': 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000AE': {'name': 'TLS_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000AF': {'name': 'TLS_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000B0': {'name': 'TLS_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '0000B1': {'name': 'TLS_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '0000B2': {'name': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000B3': {'name': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000B4': {'name': 'TLS_DHE_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '0000B5': {'name': 'TLS_DHE_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '0000B6': {'name': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000B7': {'name': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '0000B8': {'name': 'TLS_RSA_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '0000B9': {'name': 'TLS_RSA_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C001': {'name': 'TLS_ECDH_ECDSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C002': {'name': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00C003': {'name': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C004': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C005': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C006': {'name': 'TLS_ECDHE_ECDSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C007': {'name': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00C008': {'name': 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C009': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C00A': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C00B': {'name': 'TLS_ECDH_RSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C00C': {'name': 'TLS_ECDH_RSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00C00D': {'name': 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C00E': {'name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C00F': {'name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C010': {'name': 'TLS_ECDHE_RSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C011': {'name': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00C012': {'name': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C013': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C014': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C015': {'name': 'TLS_ECDH_Anon_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C016': {'name': 'TLS_ECDH_Anon_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'MEDIUM', 'overall_strength': 'MITM'},
    '00C017': {'name': 'TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00C018': {'name': 'TLS_ECDH_Anon_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00C019': {'name': 'TLS_ECDH_Anon_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'MITM', 'enc_strength': 'HIGH', 'overall_strength': 'MITM'},
    '00C01A': {'name': 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C01B': {'name': 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C01C': {'name': 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C01D': {'name': 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C01E': {'name': 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C01F': {'name': 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C020': {'name': 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C021': {'name': 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C022': {'name': 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C023': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C024': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C025': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C026': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C027': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C028': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C029': {'name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C02A': {'name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C02B': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C02C': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C02D': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C02E': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C02F': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C030': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C031': {'name': 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C032': {'name': 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C033': {'name': 'TLS_ECDHE_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
    '00C034': {'name': 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C035': {'name': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C036': {'name': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C037': {'name': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C038': {'name': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00C039': {'name': 'TLS_ECDHE_PSK_WITH_NULL_SHA ', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA ', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C03A': {'name': 'TLS_ECDHE_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00C03B': {'name': 'TLS_ECDHE_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
    '00FEFE': {'name': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '00FEFF': {'name': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00FFE0': {'name': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
    '00FFE1': {'name': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '010080': {'name': 'SSL2_RC4_128_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'MEDIUM', 'overall_strength': 'LOW'},
    '020080': {'name': 'SSL2_RC4_128_EXPORT40_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128_EXPORT40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
    '030080': {'name': 'SSL2_RC2_CBC_128_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC2_CBC_128_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '040080': {'name': 'SSL2_RC2_CBC_128_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC2_CBC_128_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '050080': {'name': 'SSL2_IDEA_128_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'IDEA_128_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'HIGH', 'overall_strength': 'LOW'},
    '060040': {'name': 'SSL2_DES_64_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'DES_64_CBC', 'bits': '64', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '0700C0': {'name': 'SSL2_DES_192_EDE3_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'DES_192_EDE3_CBC', 'bits': '192', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'HIGH', 'overall_strength': 'LOW'},
    '080080': {'name': 'SSL2_RC4_64_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_64', 'bits': '64', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '800001': {'name': 'PCT_SSL_CERT_TYPE | PCT1_CERT_X509', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '800003': {'name': 'PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '810001': {'name': 'PCT_SSL_HASH_TYPE | PCT1_HASH_MD5', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '810003': {'name': 'PCT_SSL_HASH_TYPE | PCT1_HASH_SHA', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '820001': {'name': 'PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '830004': {'name': 'PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '842840': {'name': 'PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '848040': {'name': 'PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    '8F8001': {'name': 'PCT_SSL_COMPAT | PCT_VERSION_1', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
    }



    # ADDED by VIKAs
    TLS_NULL_WITH_NULL_NULL = 0x0000
    TLS_RSA_WITH_NULL_MD5 = 0x0001
    TLS_RSA_WITH_NULL_SHA = 0x0002
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008
    TLS_RSA_WITH_DES_CBC_SHA = 0x0009
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA= 0x000B
    TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000C
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E
    TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000F
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011
    TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014
    TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017
    TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019
    TLS_DH_anon_WITH_DES_CBC_SHA = 0x001A
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B
    TLS_KRB5_WITH_DES_CBC_SHA = 0x001E
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x001F
    TLS_KRB5_WITH_RC4_128_SHA = 0x0020
    TLS_KRB5_WITH_IDEA_CBC_SHA = 0x0021
    TLS_KRB5_WITH_DES_CBC_MD5 = 0x0022
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x0023
    TLS_KRB5_WITH_RC4_128_MD5 = 0x0024
    TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x0025
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x0028
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x002B
    TLS_PSK_WITH_NULL_SHA = 0x002C
    TLS_DHE_PSK_WITH_NULL_SHA = 0x002D
    TLS_RSA_PSK_WITH_NULL_SHA = 0x002E
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A
    TLS_RSA_WITH_NULL_SHA256 = 0x003B
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x0046
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x0089
    TLS_PSK_WITH_RC4_128_SHA = 0x008A
    TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x008B
    TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C
    TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D
    TLS_DHE_PSK_WITH_RC4_128_SHA = 0x008E
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x008F
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091
    TLS_RSA_PSK_WITH_RC4_128_SHA = 0x0092
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x0093
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
    TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A
    TLS_DH_anon_WITH_SEED_CBC_SHA = 0x009B
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00A4
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00A5
    TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0x00A6
    TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0x00A7
    TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8
    TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD
    TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE
    TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF
    TLS_PSK_WITH_NULL_SHA256 = 0x00B0
    TLS_PSK_WITH_NULL_SHA384 = 0x00B1
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3
    TLS_DHE_PSK_WITH_NULL_SHA256 = 0x00B4
    TLS_DHE_PSK_WITH_NULL_SHA384 = 0x00B5
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7
    TLS_RSA_PSK_WITH_NULL_SHA256 = 0x00B8
    TLS_RSA_PSK_WITH_NULL_SHA384 = 0x00B9
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BB
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BD
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BF
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C1
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C3
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C5
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
    TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
    TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F
    TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
    TLS_ECDH_anon_WITH_NULL_SHA = 0xC015
    TLS_ECDH_anon_WITH_RC4_128_SHA = 0xC016
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032
    TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xC033
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038
    TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039
    TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A
    TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B
    TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C
    TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC03E
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC03F
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC040
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC041
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC042
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC043
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xC046
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xC047
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC054
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC055
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC056
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC057
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC058
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC059
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xC05A
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xC05B
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063
    TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064
    TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069
    TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A
    TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC080
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC081
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC082
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC083
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xC084
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xC085
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B
    TLS_RSA_WITH_AES_128_CCM = 0xC09C
    TLS_RSA_WITH_AES_256_CCM = 0xC09D
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F
    TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0
    TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3
    TLS_PSK_WITH_AES_128_CCM = 0xC0A4
    TLS_PSK_WITH_AES_256_CCM = 0xC0A5
    TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6
    TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7
    TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8
    TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9
    TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xC0AA
    TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xC0AB
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B
    TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034

    all_suites = []
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_PSK_WITH_RC4_128_SHA)
    all_suites.append(TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_PSK_WITH_NULL_SHA)
    all_suites.append(TLS_ECDHE_PSK_WITH_NULL_SHA256)
    all_suites.append(TLS_ECDHE_PSK_WITH_NULL_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)
    all_suites.append(TLS_ECDHE_RSA_WITH_RC4_128_SHA)
    all_suites.append(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_NULL_SHA)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_NULL_WITH_NULL_NULL)
    all_suites.append(TLS_RSA_WITH_NULL_MD5)
    all_suites.append(TLS_RSA_WITH_NULL_SHA)
    all_suites.append(TLS_RSA_EXPORT_WITH_RC4_40_MD5)
    all_suites.append(TLS_RSA_WITH_RC4_128_MD5)
    all_suites.append(TLS_RSA_WITH_RC4_128_SHA)
    all_suites.append(TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5)
    all_suites.append(TLS_RSA_WITH_IDEA_CBC_SHA)
    all_suites.append(TLS_RSA_EXPORT_WITH_DES40_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_DES_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_DES_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_DES_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_DES_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_DES_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_DH_anon_EXPORT_WITH_RC4_40_MD5)
    all_suites.append(TLS_DH_anon_WITH_RC4_128_MD5)
    all_suites.append(TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_DES_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_KRB5_WITH_DES_CBC_SHA)
    all_suites.append(TLS_KRB5_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_KRB5_WITH_RC4_128_SHA)
    all_suites.append(TLS_KRB5_WITH_IDEA_CBC_SHA)
    all_suites.append(TLS_KRB5_WITH_DES_CBC_MD5)
    all_suites.append(TLS_KRB5_WITH_3DES_EDE_CBC_MD5)
    all_suites.append(TLS_KRB5_WITH_RC4_128_MD5)
    all_suites.append(TLS_KRB5_WITH_IDEA_CBC_MD5)
    all_suites.append(TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA)
    all_suites.append(TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA)
    all_suites.append(TLS_KRB5_EXPORT_WITH_RC4_40_SHA)
    all_suites.append(TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5)
    all_suites.append(TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5)
    all_suites.append(TLS_KRB5_EXPORT_WITH_RC4_40_MD5)
    all_suites.append(TLS_PSK_WITH_NULL_SHA)
    all_suites.append(TLS_DHE_PSK_WITH_NULL_SHA)
    all_suites.append(TLS_RSA_PSK_WITH_NULL_SHA)
    all_suites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_NULL_SHA256)
    all_suites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_AES_256_CBC_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_AES_256_CBC_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    all_suites.append(TLS_DH_anon_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_DH_anon_WITH_AES_256_CBC_SHA256)
    all_suites.append(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA)
    all_suites.append(TLS_PSK_WITH_RC4_128_SHA)
    all_suites.append(TLS_PSK_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_PSK_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_PSK_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_DHE_PSK_WITH_RC4_128_SHA)
    all_suites.append(TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_DHE_PSK_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_DHE_PSK_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_RSA_PSK_WITH_RC4_128_SHA)
    all_suites.append(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_RSA_PSK_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_RSA_PSK_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_SEED_CBC_SHA)
    all_suites.append(TLS_DH_DSS_WITH_SEED_CBC_SHA)
    all_suites.append(TLS_DH_RSA_WITH_SEED_CBC_SHA)
    all_suites.append(TLS_DHE_DSS_WITH_SEED_CBC_SHA)
    all_suites.append(TLS_DHE_RSA_WITH_SEED_CBC_SHA)
    all_suites.append(TLS_DH_anon_WITH_SEED_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_RSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_DH_RSA_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_DH_DSS_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_DH_anon_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_DH_anon_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_PSK_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_PSK_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_AES_128_GCM_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_AES_256_GCM_SHA384)
    all_suites.append(TLS_PSK_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_PSK_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_PSK_WITH_NULL_SHA256)
    all_suites.append(TLS_PSK_WITH_NULL_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_NULL_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_NULL_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_AES_128_CBC_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_AES_256_CBC_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_NULL_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_NULL_SHA384)
    all_suites.append(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256)
    all_suites.append(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256)
    all_suites.append(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    all_suites.append(TLS_ECDH_ECDSA_WITH_NULL_SHA)
    all_suites.append(TLS_ECDH_ECDSA_WITH_RC4_128_SHA)
    all_suites.append(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_ECDH_RSA_WITH_NULL_SHA)
    all_suites.append(TLS_ECDH_RSA_WITH_RC4_128_SHA)
    all_suites.append(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_ECDH_anon_WITH_NULL_SHA)
    all_suites.append(TLS_ECDH_anon_WITH_RC4_128_SHA)
    all_suites.append(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_ECDH_anon_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_ECDH_anon_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA)
    all_suites.append(TLS_RSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_RSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_DH_anon_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_DH_anon_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_RSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_RSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_DH_anon_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_DH_anon_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_PSK_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_PSK_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_PSK_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_PSK_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384)
    all_suites.append(TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256)
    all_suites.append(TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384)
    all_suites.append(TLS_RSA_WITH_AES_128_CCM)
    all_suites.append(TLS_RSA_WITH_AES_256_CCM)
    all_suites.append(TLS_DHE_RSA_WITH_AES_128_CCM)
    all_suites.append(TLS_DHE_RSA_WITH_AES_256_CCM)
    all_suites.append(TLS_RSA_WITH_AES_128_CCM_8)
    all_suites.append(TLS_RSA_WITH_AES_256_CCM_8)
    all_suites.append(TLS_DHE_RSA_WITH_AES_128_CCM_8)
    all_suites.append(TLS_DHE_RSA_WITH_AES_256_CCM_8)
    all_suites.append(TLS_PSK_WITH_AES_128_CCM)
    all_suites.append(TLS_PSK_WITH_AES_256_CCM)
    all_suites.append(TLS_DHE_PSK_WITH_AES_128_CCM)
    all_suites.append(TLS_DHE_PSK_WITH_AES_256_CCM)
    all_suites.append(TLS_PSK_WITH_AES_128_CCM_8)
    all_suites.append(TLS_PSK_WITH_AES_256_CCM_8)
    all_suites.append(TLS_PSK_DHE_WITH_AES_128_CCM_8)
    all_suites.append(TLS_PSK_DHE_WITH_AES_256_CCM_8)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CCM)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CCM)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
    all_suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8)

    #existing ciphers
    tripleDESSuites = []
    tripleDESSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)

    aes128Suites = []
    aes128Suites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DH_anon_WITH_AES_128_CBC_SHA)

    aes256Suites = []
    aes256Suites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DH_anon_WITH_AES_256_CBC_SHA)

    rc4Suites = []
    rc4Suites.append(TLS_RSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_RSA_WITH_RC4_128_MD5)

    shaSuites = []
    shaSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_DH_anon_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DH_anon_WITH_AES_256_CBC_SHA)

    ecdheSuites = []
    ecdheSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)
    ecdheSuites.append(TLS_ECDHE_RSA_WITH_RC4_128_SHA)
    ecdheSuites.append(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
    ecdheSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    ecdheSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    ecdheSuites.append(TLS_ECDHE_ECDSA_WITH_NULL_SHA)
    ecdheSuites.append(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
    ecdheSuites.append(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    ecdheSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
    ecdheSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)

    #ecdheSuites.append(ECDHE-ECDSA-DES-CBC3-SHA)
    #ecdheSuites.append(ECDHE-ECDSA-AES128-SHA)
    #ecdheSuites.append(ECDHE-ECDSA-AES256-SHA)
    #ecdheSuites.append(ECDHE-RSA-RC4-SHA)
    #ecdheSuites.append(ECDHE-RSA-DES-CBC3-SHA)
    #ecdheSuites.append(ECDHE-RSA-AES128-SHA)
    #ecdheSuites.append(ECDHE-RSA-AES256-SHA)
    #ecdheSuites.append(ECDHE-ECDSA-NULL-SHA)
    #ecdheSuites.append(ECDHE-ECDSA-RC4-SHA)
    #ecdheSuites.append(ECDHE-RSA-NULL-SHA)

    ecdheSuites.append(TLS_RSA_WITH_NULL_SHA256)
    ecdheSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    ecdheSuites.append(TLS_RSA_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_RSA_WITH_AES_256_GCM_SHA384)
    ecdheSuites.append(TLS_DH_RSA_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_DH_RSA_WITH_AES_256_CBC_SHA256)
    ecdheSuites.append(TLS_DH_RSA_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_DH_RSA_WITH_AES_256_GCM_SHA384)
    ecdheSuites.append(TLS_DH_DSS_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_DH_DSS_WITH_AES_256_CBC_SHA256)
    ecdheSuites.append(TLS_DH_DSS_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_DH_DSS_WITH_AES_256_GCM_SHA384)
    ecdheSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    ecdheSuites.append(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
    ecdheSuites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)
    ecdheSuites.append(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384)
    ecdheSuites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384)
    ecdheSuites.append(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384)
    ecdheSuites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256)
    ecdheSuites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384)
    ecdheSuites.append(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256)
    ecdheSuites.append(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384)

    #ecdheSuites.append(NULL-SHA256)
    #ecdheSuites.append(AES128-SHA256)
    #ecdheSuites.append(AES256-SHA256)
    #ecdheSuites.append(AES128-GCM-SHA256)
    #ecdheSuites.append(AES256-GCM-SHA384)
    #ecdheSuites.append(DH-RSA-AES128-SHA256)
    #ecdheSuites.append(DH-RSA-AES256-SHA256)
    #ecdheSuites.append(DH-RSA-AES128-GCM-SHA256)
    #ecdheSuites.append(DH-RSA-AES256-GCM-SHA384)
    #ecdheSuites.append(DH-DSS-AES128-SHA256)
    #ecdheSuites.append(DH-DSS-AES256-SHA256)
    #ecdheSuites.append(DH-DSS-AES128-GCM-SHA256)
    #ecdheSuites.append(DH-DSS-AES256-GCM-SHA384)
    #ecdheSuites.append(DHE-RSA-AES128-SHA256)
    #ecdheSuites.append(DHE-RSA-AES256-SHA256)
    #ecdheSuites.append(DHE-RSA-AES128-GCM-SHA256)
    #ecdheSuites.append(DHE-RSA-AES256-GCM-SHA384)
    #ecdheSuites.append(DHE-DSS-AES128-SHA256)
    #ecdheSuites.append(DHE-DSS-AES256-SHA256)
    #ecdheSuites.append(DHE-DSS-AES128-GCM-SHA256)
    #ecdheSuites.append(DHE-DSS-AES256-GCM-SHA384)
    #ecdheSuites.append(ECDH-RSA-AES128-SHA256)
    #ecdheSuites.append(ECDH-RSA-AES256-SHA384)
    #ecdheSuites.append(ECDH-RSA-AES128-GCM-SHA256)
    #ecdheSuites.append(ECDH-RSA-AES256-GCM-SHA384)
    #ecdheSuites.append(ECDH-ECDSA-AES128-SHA256)
    #ecdheSuites.append(ECDH-ECDSA-AES256-SHA384)
    #ecdheSuites.append(ECDH-ECDSA-AES128-GCM-SHA256)
    #ecdheSuites.append(ECDH-ECDSA-AES256-GCM-SHA384)

    md5Suites = []
    md5Suites.append(TLS_RSA_WITH_RC4_128_MD5)

    @staticmethod
    def _filterSuites(suites, settings):
        macNames = settings.macNames
        cipherNames = settings.cipherNames
        macSuites = []
        if "sha" in macNames:
            macSuites += CipherSuite.shaSuites
        if "md5" in macNames:
            macSuites += CipherSuite.md5Suites

        cipherSuites = []
        if "aes128" in cipherNames:
            cipherSuites += CipherSuite.aes128Suites
        if "aes256" in cipherNames:
            cipherSuites += CipherSuite.aes256Suites
        if "3des" in cipherNames:
            cipherSuites += CipherSuite.tripleDESSuites
        if "rc4" in cipherNames:
            cipherSuites += CipherSuite.rc4Suites

        return [s for s in suites if s in macSuites and s in cipherSuites]

    srpSuites = []
    srpSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    srpSuites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    srpSuites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)

    @staticmethod
    def getSrpSuites(settings):
        return CipherSuite._filterSuites(CipherSuite.srpSuites, settings)

    srpCertSuites = []
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)

    @staticmethod
    def getSrpCertSuites(settings):
        return CipherSuite._filterSuites(CipherSuite.srpCertSuites, settings)

    srpAllSuites = srpSuites + srpCertSuites

    @staticmethod
    def getSrpAllSuites(settings):
        return CipherSuite._filterSuites(CipherSuite.srpAllSuites, settings)

    certSuites = []
    certSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_RC4_128_SHA)
    certSuites.append(TLS_RSA_WITH_RC4_128_MD5)
    certAllSuites = srpCertSuites + certSuites

    @staticmethod
    def getCertSuites(settings):
        return CipherSuite._filterSuites(CipherSuite.certSuites, settings)

    anonSuites = []
    anonSuites.append(TLS_DH_anon_WITH_AES_128_CBC_SHA)
    anonSuites.append(TLS_DH_anon_WITH_AES_256_CBC_SHA)

    @staticmethod
    def getAnonSuites(settings):
        return CipherSuite._filterSuites(CipherSuite.anonSuites, settings)

    @staticmethod
    def canonicalCipherName(ciphersuite):
        "Return the canonical name of the cipher whose number is provided."
        if ciphersuite in CipherSuite.aes128Suites:
            return "aes128"
        elif ciphersuite in CipherSuite.aes256Suites:
            return "aes256"
        elif ciphersuite in CipherSuite.rc4Suites:
            return "rc4"
        elif ciphersuite in CipherSuite.tripleDESSuites:
            return "3des"
        else:
            return None

    @staticmethod
    def canonicalMacName(ciphersuite):
        "Return the canonical name of the MAC whose number is provided."
        if ciphersuite in CipherSuite.shaSuites:
            return "sha"
        elif ciphersuite in CipherSuite.md5Suites:
            return "md5"
        else:
            return None


# The following faults are induced as part of testing.  The faultAlerts
# dictionary describes the allowed alerts that may be triggered by these
# faults.
class Fault:
    badUsername = 101
    badPassword = 102
    badA = 103
    clientSrpFaults = list(range(101,104))

    badVerifyMessage = 601
    clientCertFaults = list(range(601,602))

    badPremasterPadding = 501
    shortPremasterSecret = 502
    clientNoAuthFaults = list(range(501,503))

    badB = 201
    serverFaults = list(range(201,202))

    badFinished = 300
    badMAC = 301
    badPadding = 302
    genericFaults = list(range(300,303))

    faultAlerts = {\
        badUsername: (AlertDescription.unknown_psk_identity, \
                      AlertDescription.bad_record_mac),\
        badPassword: (AlertDescription.bad_record_mac,),\
        badA: (AlertDescription.illegal_parameter,),\
        badPremasterPadding: (AlertDescription.bad_record_mac,),\
        shortPremasterSecret: (AlertDescription.bad_record_mac,),\
        badVerifyMessage: (AlertDescription.decrypt_error,),\
        badFinished: (AlertDescription.decrypt_error,),\
        badMAC: (AlertDescription.bad_record_mac,),\
        badPadding: (AlertDescription.bad_record_mac,)
        }

    faultNames = {\
        badUsername: "bad username",\
        badPassword: "bad password",\
        badA: "bad A",\
        badPremasterPadding: "bad premaster padding",\
        shortPremasterSecret: "short premaster secret",\
        badVerifyMessage: "bad verify message",\
        badFinished: "bad finished message",\
        badMAC: "bad MAC",\
        badPadding: "bad padding"
        }
