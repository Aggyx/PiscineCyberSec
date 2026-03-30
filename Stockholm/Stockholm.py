import argparse
import os
from Crypto.PublicKey import RSA
from secrets import token_bytes

def arg_parser():
    try:
        argv_parser = argparse.ArgumentParser(
            prog="Stockholm",
            description='./stockholm A program to encrypt the contents of the files in a folder',
            epilog='Piscina Cyberseguridad - smagniny',
            add_help=False
        )
        argv_parser.add_argument('-h', '--help', help='Display the help message', action="store_true")
        argv_parser.add_argument('-v', '--version', help='Shows the version of the program', action="store_true")
        argv_parser.add_argument('-r', '--reverse', help='Reverse the infection !', action="store")
        argv_parser.add_argument('-s', '--silent', help='The program will not produce any output', action="store_true")
        argv = argv_parser.parse_args()

        return argv.help, argv.version, argv.reverse, argv.silent
    except Exception as E:
        print(str(E))



class Stockholm:

    default_route = "infection"
    def __init__(self, help=False, version=False, reverse=False, silent=False):
        self.help = help
        self.version = version
        self.reverse = reverse
        self.silent = silent
        self.key_path = f"{os.path.expanduser('~')}/KEY_Stockholm_KEY.pem"
        self.__generar_llave()
    

    def __generar_llave(self):
        self.password = token_bytes(128) # https://docs.python.org/3/library/secrets.html#secrets.token_bytes
        self.mysuperkey = RSA.generate(4096) # cambiar N 
        tmpkey = None
        try:
            with open(self.key_path, "wb") as f:
                key = self.mysuperkey(passphrase=self.key_path,
                                      pkcs=8,
                                      protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                      prot_params={'iteration_count':21000}
                )
                tmpkey = str(key)
                f.write(key)
            print(f"Llave generada en '{self.key_path}'.")
            print("   llave: ", tmpkey)
        except Exception as E:
            print(str(E))

    def __import_llave(self):
        with open(self.key_path, "rb") as f:
            key = f.read()
            print(RSA.import_key(key, self.password))
    
    def __export_llave(self):
        publickey_path = f"{os.path.expanduser('~')}/PUBLIC_KEY_Stockholm_PUBLIC_KEY.pem"
        with open(self.key_path, "wb") as f:
            pub = mykey.public_key().export_key()
            f.write(pub)

    def __stockholm(self):
        pass

    def __paris(self):
        pass

        


if __name__ == "__main__":
    help, version, reverse, silent = arg_parser()
    
    goodware = Stockholm(help, version, reverse, silent)

