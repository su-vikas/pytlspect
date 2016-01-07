pyTLSpect
=========
pyTLSpect is a SSL/TLS scanner written purely in Python. The project was started to learn about internals of SSL/TLS, and implementing SSL/TLS is the best way to learn the nitty-gritties of it. I am trying to emulate Qualys SSLLabs analysis tool. Although there are many other much mature and advance tools available to do the same, to name a few: sslyze (https://github.com/iSECPartners/sslyze), sslscan (https://github.com/rbsec/sslscan ) and many others. 

TLSlite project (https://github.com/trevp/tlslite) is used as the base to start with and critical part is borrowed/inspired from the project. 

At present the TLSpect can perform following analysis:

* SSL/TLS versions supported
* SSL/TLS ciphersuites supported for each version
* Certificate chain information and their expiry validation
* SSL/TLS extensions supported
* Test for POODLE

Still the tool is underdevelopment. Please go through the TODO list if you want to contribute. 
USAGE
-------

To scan a HTTPS website:
usage: tlspect.py [-h] -d HOST [-p PORT] [-a] [-P] [-H] [-F] [-L]

Scan for various TLS configurations

optional arguments:
  -h, --help            show this help message and exit
  -d HOST, --domain HOST
                        The hostname to be scanned for
  -p PORT, --port PORT  Port number to scan at, defaults to 443
  -a, --all             Scan for all parameters
  -P, --poodle          Test for POODLE SSL attack
  -H, --heartbleed      Test for Heartbled SSL vulnerability
  -F, --freak           Test for FREAK SSL vulnerability
  -L, --logjam          Test for LOGJAM SSL vulnerability


REQUIREMENTS
-------------

* M2Crypto/OpenSSL (these are optional, will work without them as well)
* pewee for storing data to database. 

LICENSE
-------
The code is released under MIT License. To read more about it and what does it means for humans, visit http://choosealicense.com/licenses/mit/ 
