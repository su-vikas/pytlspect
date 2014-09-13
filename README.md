pyTLSpect
=========
A SSL/TLS scanner written in python. The output includes TLS versions supported, TLS ciphersuites supported in server preferred order, TLS extensions supported, x509 certificate information   

There are many TLS scanner already available. The reason to write another such tool is totally for learning purpose. 

The underlying packet handling code is inspired from TLSlite project. (https://github.com/trevp/tlslite)

Presently, the code is still work under progess and hence not stable yet. Some crashes are still observed here and there.

USAGE
-------
Currently, it cannot be installed. It should be used directly as a script. 

To scan a HTTPS website:
        tlspect.py -d google.com

Requirements
* M2Crypto
* pewee for storing data to database. 

LICENSE
-------
The code is released under MIT License. To read more about it and what does it means for humans, visit http://choosealicense.com/licenses/mit/ 
