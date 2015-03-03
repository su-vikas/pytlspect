TLSpect
=========
A SSL/TLS scanner written in python. The aim of the project to replicate ssllabs SSL analysis tool. The core code of the project is heavily borrowed from TLSlite project (https://github.com/trevp/tlslite).

At present the TLSpect can perform following analysis:
- SSL/TLS versions supported
- SSL/TLS ciphersuites supported for each version
- Certificate chain information and their expiry validation
- SSL/TLS extensions supported
- Test for POODLE

and some other minor features. Other features envisaged are on the lines of ssllabs tool. 

Presently, the code is still work under progess and hence not stable yet. Some crashes are still observed here and there.

USAGE
-------
Currently, it cannot be installed. It should be used directly as a script. 

To scan a HTTPS website:
        tlspect.py -d google.com

Requirements
* M2Crypto/OpenSSL (these are optional, will work without them as well)
* pewee for storing data to database. 

LICENSE
-------
The code is released under MIT License. To read more about it and what does it means for humans, visit http://choosealicense.com/licenses/mit/ 
