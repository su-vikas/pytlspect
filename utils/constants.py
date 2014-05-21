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


    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF

    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA  = 0xC01A
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020

    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021


    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_RSA_WITH_RC4_128_SHA = 0x0005

    TLS_RSA_WITH_RC4_128_MD5 = 0x0004

    TLS_DH_ANON_WITH_AES_128_CBC_SHA = 0x0034
    TLS_DH_ANON_WITH_AES_256_CBC_SHA = 0x003A

    tripleDESSuites = []
    tripleDESSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)

    aes128Suites = []
    aes128Suites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)

    aes256Suites = []
    aes256Suites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)

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
    shaSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)

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
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)

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
