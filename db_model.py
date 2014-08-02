from peewee import *
import peewee as pw
import datetime

DATABASE = "TLSScanning"

myDB = pw.MySQLDatabase("TLSScanning", host="127.0.0.1", port=3306, user="root", passwd="fedora")

# define a base model calss that specifies which database to use. Then, any subclasses
# will automatically use the correct DB.
class BaseModel(Model):
    class Meta:
        database = myDB

# contains TLS protocol configuration related information
class TLSConfiguration(BaseModel):
    tls_config_id = PrimaryKeyField()
    protocol_version = CharField()                          # TLS version supported
    ciphersuites = CharField()                              # ciphersuites supported by this website
    compression = BooleanField()                               # which all compression method are supported.

# contains x509 certificate related information
class CertificateConfiguration(BaseModel):
    cert_id  =  PrimaryKeyField()                           # id for this table
    serial_number = CharField()                             # certificate's serial number
    signature_algorithm = CharField()                       # signature algorithm
    common_name = CharField()                               # common name for the certificate
    alternative_name = CharField()                          # alternative name extracted from the alt_name x509 extension
    valid_from = DateTimeField()                            # valid from
    valid_until = DateTimeField()                           # valid until
    key_size = CharField()                                  # size of the public key advertised
    key_algorithm = CharField()                             # algorithm of the key
    issuer = CharField()                                    # issuer of the certificate
    sha1_fingerprint = CharField()                          # sha1 fingerprint of the certificate

# many-to-many relationship for certificates contained in the cert chain
class CertificateChain(BaseModel):
    cert_chain_id = IntegerField()                          # id of the certificate chain
    cert_id = ForeignKeyField(CertificateConfiguration)     # certificate id present in this chain

# table containing basic information about the scan
class TLSScan(BaseModel):
    tls_scan_id = PrimaryKeyField()                         # id for this table
    domain = CharField(null=False)                          # domain of the application scanned against
    ip = CharField(null=False)                              # ip of the domain scanned
    app_id = IntegerField(null=False)                       # application id from app info db
    tls_supported = BooleanField(null=False)                # whether the site is tls/ssl enabled
    cert_number = IntegerField()                            # number of certificates in the chain
    tls_config_id = ForeignKeyField(TLSConfiguration)       # link to TLS configuration table
    cert_chain_id = ForeignKeyField(CertificateChain)       # link the certificate configuration table
    time_scanned = DateTimeField(default = datetime.datetime.now, null=False) # time of scanning

