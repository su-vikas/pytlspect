from base64 import b64decode, b64encode
from urllib import quote, unquote

import socket, struct, time, random
from HTTPResponseParser import parse_http_response
from nassl import _nassl, SSL_VERFIY_NONE
from nassl.SslClient import SslClient, ClientCertificateRequested


class SSLTunnelConnection:
    """SSL connection class that connects to a server through a CONNECT proxy """
