from db_model import TLSScan,TLSConfiguration,CertificateConfiguration,CertificateChain
from db_model import *

class DBManager:

    def create_tables(self):
        TLSConfiguration.create_table()
        CertificateConfiguration.create_table()
        CertificateChain.create_table()
        TLSScan.create_table()




def main():
    mang = DBManager()
    mang.create_tables()

if __name__ == "__main__":
    main()




