TLSpect
=========
A SSL/TLS scanner written in python. The aim of the project to replicate ssllabs SSL analysis tool. The core code of the project is heavily borrowed from TLSlite project (https://github.com/trevp/tlslite).

At present the TLSpect can perform following analysis:
* SSL/TLS versions supported
* SSL/TLS ciphersuites supported for each version
* Certificate chain information and their expiry validation
* SSL/TLS extensions supported
* Test for POODLE

and some other features. Other features envisaged are on the lines of ssllabs tool. 

Presently, the code is still work under progess and hence not stable yet. Some crashes are still observed here and there.

USAGE
-------
Currently, it cannot be installed. It should be used directly as a script. 

To scan a HTTPS website:
usage: tlspect.py [-h] -d HOST [-p PORT] [-a] [-v VERSION] [-c] [-z] [-t] [-w]
                  [-C] [-s] [-e] [-P] [-H]

Scan for various TLS configurations

optional arguments:
* -h, --help            show this help message and exit
* -d HOST, --domain HOST
*                       The hostname to be scanned for
* -p PORT, --port PORT  Port number to scan at, defaults to 443
* -a, --all             Scan for all parameters
* -v VERSION, --version VERSION
*                       SSL version to scan for
* -c, --ciphers         Scan only for ciphers supported
* -z, --compression     Scan only for if compression supported
* -t, --tls-versions    Scan only for supported TLS versions
* -w, --weak-ciphers    Report potentially weak ciphers only
* -C, --cert            Show certificate details
* -s, --cert-chain      Show certificate chain details
* -e, --tls-ext         Show supported TLS extensions
* -P, --poodle          Test for Poodle SSL attack

REQUIREMENTS
-------------

* M2Crypto/OpenSSL (these are optional, will work without them as well)
* pewee for storing data to database. 

LICENSE
-------
The code is released under MIT License. To read more about it and what does it means for humans, visit http://choosealicense.com/licenses/mit/ 
