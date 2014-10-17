import os
from os.path import join, isfile
from distutils.core import setup


setup(name="tlspect",
        version="0.1",
        description="TLS scanner",
        long_description="""A SSL/TLS configuration scanner, determines TLS versions, ciphersuites used and x509 certificate information.""",
        license = "MIT",
        author = "Vikas Gupta",
        url = "https://github.com/su-vikas/pytlspect",
        package_dir = {},
        packages = ['tlspect'],
        scripts=scrip
        )
