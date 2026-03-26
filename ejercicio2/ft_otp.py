'''
https://datatracker.ietf.org/doc/html/rfc4226#section-5.3

Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS is a 20-byte string

Step 2: Generate a 4-byte string (Dynamic Truncation)
Let Sbits = DT(HS)   //  DT, defined below,
                    //  returns a 31-bit string

Step 3: Compute an HOTP value
Let Snum  = StToNum(Sbits)   // Convert S to a number in
                                0...2^{31}-1
Return D = Snum mod 10^Digit //  D is a number in the range
                                0...10^{Digit}-1
'''
from cryptography.fernet import Fernet
import hmac
import hashlib
import argparse
import time
import re


def arg_parser() -> tuple:
    try:
        argv_parser = argparse.ArgumentParser(prog='ft_otp',description='./ft_otp\n A program that allows you to store an initial password in file, and that is capable of generating a new one time password every time it is requested.', epilog='Piscina Cyberseguridad - HOTP - smagniny')
        argv_parser.add_argument('-g', help='The program receives as argument a hexadecimal key of at least 64 characters. The program stores this key safely in a file called ft_otp.key, whichis encrypted')
        argv_parser.add_argument('-k', help='The program generates a new temporary password based on the key given as argument and prints it on the standard output')
        
        argv = argv_parser.parse_args()

        if not argv.g and not argv.k:
            argv_parser.print_help()
            exit(0)

        return argv.g, argv.k
    except Exception as E:
        print(str(E))


class HOTP:
    def __init__(self, g=None, k=None):
        print(f"Generar llave: {g}, Crear OTP: {k}")
        self.g = g
        self.k = k
        self.__supersemilla = b'NxUmN9_W7EaOEAnIH54yM0YTviqhL131Yo6AqfeyTrw=' # previamente generado con Fernet.generate_key() en el REPL
        self.cryptographyy = Fernet(self.__supersemilla)

        if g:
            self.generar_llave(g)
        elif k:
            self.crear_otp()

    def generar_llave(self, llave_hexadecimal_o_archivo):
        def validar_entrada(entrada: str):
	        return (len(entrada) >= 64 and bool(re.fullmatch("[0-9a-fA-F]+", entrada)))

        contenido_en_bytes = None
        flag_archivo = False
        try:
            with open(llave_hexadecimal_o_archivo, "r") as fd:
                contenido = fd.read()
            if not validar_entrada(contenido):
                raise Exception("La llave debe tener al menos 64 caracteres hexadecimales")
            flag_archivo = True
            contenido_en_bytes = bytes.fromhex(contenido)
        except Exception as E:
            flag_archivo = False
            pass

        if flag_archivo == False: # No se ha podido abrir el archivo, la entrada es la llave hexadecimal
            if not validar_entrada(llave_hexadecimal_o_archivo):
                    print("La llave debe tener al menos 64 caracteres hexadecimales")
                    return
            contenido_en_bytes = bytes.fromhex(llave_hexadecimal_o_archivo)
        # Para ambos casos
        llave_encriptada = self.cryptographyy.encrypt(contenido_en_bytes)
        with open("ft_otp.key", "wb") as fd:
            fd.write(llave_encriptada)
        print("Llave almacenada correctamente en ft_otp.key")

    def crear_otp(self):
        '''
        https://datatracker.ietf.org/doc/html/rfc4226#section-5.3
        https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
        '''
        try:
            with open("ft_otp.key", "rb") as fd:
                llave_encriptada = fd.read()
            llave_desencriptada = self.cryptographyy.decrypt(llave_encriptada)
        except Exception as E:
            print(str(E))
            return

        # Para generar el OTP, se necesita un contador (C) que se incrementa cada vez que se genera un nuevo OTP
        # En este caso, se puede usar el tiempo actual en segundos como contador
        C = int(time.time()) // 30 # Se divide por 30 para que el OTP cambie cada 30 segundos
        # Generar HMAC-SHA-1 (es la combinacion de los dos algoritmos, el de hash y el de encriptacion)
        HS = hmac.new(llave_desencriptada, C.to_bytes(8, byteorder='big'), hashlib.sha1).digest()
        # 'Dynamic Truncation'
        offset = HS[-1] & 0x0F # -1 porque en el rfc dice de 20 bytes y sacan el 19
        Sbits = HS[offset:offset+4] #avanzar 4 bytes a partir del offset
        Snum = int.from_bytes(Sbits, byteorder='big') & 0x7FFFFFFF # Para obtener un número de 31 bits
        D = Snum % 1000000  # Para obtener un OTP de 6 dígitos
        print(f"HOTP generado: {D:06d}")

if __name__ == "__main__":
    generar_llave, crear_otp = arg_parser()

    ft_otp = HOTP(generar_llave, crear_otp)
