from db_model import TLSScan,TLSConfiguration,CertificateConfiguration,CertificateChain

class DBManager:

    def create_tables(self):
        TLSScan.create_table()
        TLSConfiguration.create_table()
        CertificateConfiguration.create_table()
        CertificateChain.create_table()




def main():
    mang = DBManager()
    mang.create_tables()

if __name__ == "__main__":
    main()




