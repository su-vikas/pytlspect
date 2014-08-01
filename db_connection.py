from peewee import *
import peewee as pw

myDB = pw.MySQLDatabase("mydb", host=" ", port= "", user=" ", password=" ")

class ProtocolConfiguration(Model):
    ssl_id = IntegerField(primary_key = True)
    domain = CharField()
    protocol_version = CharField()
    ciphersuites = CharField()
    compression = CharField()
    time_scanned = DateTimeField()
    certificate_chain_id  = ForeignKeyField()

    class Meta:
        database = myDB

class CertificateConfiguration(Model):
    cert_id  = IntegerField(primary_key  = True)
    serial_number = CharField()
    signature_algorithm = CharField()
    common_name = CharField()
    alternative_name = CharField()
    valid_from = DateTimeField()
    valid_until = DateTimeField()
    key_size = CharField()
    key_algorithm = CharField()
    issuer = CharField()
    sha1_fingerprint = CharField()

    class Meta:
        database = myDB

class CertificateChain(Model):
    cert_chain_number = IntegerField()
    cert_chain = CharField() #
    certificate_chain_id = ForeignKeyField()


