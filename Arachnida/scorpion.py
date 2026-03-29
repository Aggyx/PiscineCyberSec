import argparse
import os
from datetime import datetime
from pathlib import Path
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

"""
Scorpion program receive image files as parameters and must be able to
parse them for EXIF and other metadata, displaying them on the screen.
The program must at least be compatible with the same extensions that spider handles.
It display basic attributes such as the creation date, as well as EXIF data. The output format is up to you.
./scorpion FILE1 [FILE2 ...]


el problema es que lo distintos tipos de fotos no almacenan los metadatos de la misma forma, y a veces no los almacenan. 

EXIF es soportado completamente por .jpg y .jpeg, pero no es un estandar para otros tipos de imagen.

.jpg, .jpeg  EXIF support
.png no standard EXIF, metadatos en texto
.gif no standard EXIF, metadatos con campos limitados e diferentes probablemente
.bmp no standard EXIF, metadatos con campos limitados e diferentes probablemente

"""


def arg_parser():
    try:
        #https://docs.python.org/3/library/argparse.html#nargs
        argv_parser = argparse.ArgumentParser(prog='Scorpion',description='./scorpion FILE1 [FILE2 ...]\nScorpion es un programa lee los metadatos de las imagenes', epilog='Piscina Cyberseguridad - smagniny')
        argv_parser.add_argument('FILE', help='Indica los archivos de imagen a analizar', nargs='+')
        argv = argv_parser.parse_args()

        return argv.FILE
    except Exception as E:
        print(str(E))

class Scorpion:
    def __init__(self, archivos):
        self.archivos = archivos
        self.__archivos_soportados = (".jpg", ".jpeg", ".png", ".gif", ".bmp")

    def _es_soportado(self, archivo):
        #suffix devuevle la extension con el punto incluiddo
        return Path(archivo).suffix.lower() in self.__archivos_soportados

    def _fechas_archivo(self, archivo):
        stat = os.stat(archivo)
        return {
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds"),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(sep=" ", timespec="seconds"),
        }

    def _extraer_exif(self, im):
        '''
        Retorna el diccionario de etiquetas EXIF con nombres legibles, 
        o un diccionario vacío si no hay EXIF o no es soportado.
        '''

        exif = {}
        exif_raw = im.getexif()
        if not exif_raw:
            return exif
        # Extraer y decodificar etiquetas EXIF usando TAGS de PIL.ExifTags
        for tag_id, value in exif_raw.items():
            nombre = TAGS.get(tag_id, f"Tag_{tag_id}")
            exif[nombre] = value
        return exif

    def _formatear_valor(self, valor):
        if isinstance(valor, bytes):
            return f"<bytes: {len(valor)} bytes>"
        return str(valor)

    def _racional_a_float(self, valor):
        try:
            #Funciona con tuplas (num, den) o con objetos que tengan numerator y denominator
            if isinstance(valor, tuple) and len(valor) == 2:
                num, den = valor
                return float(num) / float(den)

            # Al parecer podemos tener objetos con numerator y denominator, lo agrego por si aca
            if hasattr(valor, "numerator") and hasattr(valor, "denominator"):
                return float(valor.numerator) / float(valor.denominator)
            return float(valor)
        except Exception:
            return None

    def _coord_gps_a_decimal(self, coord, ref):
        if not coord or len(coord) != 3:
            return None

        grados = self._racional_a_float(coord[0])
        minutos = self._racional_a_float(coord[1])
        segundos = self._racional_a_float(coord[2])

        if None in (grados, minutos, segundos):
            return None

        decimal = grados + (minutos / 60.0) + (segundos / 3600.0) 
        # La formula para convertir a decimal es grados + minutos/60 + segundos/3600
        if str(ref).upper() in ("S", "W"):
            decimal *= -1

        return decimal

    def _extraer_gps_bonito(self, exif):
        gps = exif.get("GPSInfo")
        if not isinstance(gps, dict):
            return None

        gps_decodificado = {}
        for k, v in gps.items():
            clave = GPSTAGS.get(k, k)
            gps_decodificado[clave] = v

        lat = self._coord_gps_a_decimal(
            gps_decodificado.get("GPSLatitude"),
            gps_decodificado.get("GPSLatitudeRef"),
        )
        lon = self._coord_gps_a_decimal(
            gps_decodificado.get("GPSLongitude"),
            gps_decodificado.get("GPSLongitudeRef"),
        )

        if lat is None or lon is None:
            return None
        return f"{lat:.6f}, {lon:.6f}"

    def _campos_clave_bonitos(self, metadatos):
        exif = metadatos.get("exif", {})
        info = metadatos.get("info", {})

        # esta funcion me evita tener un moonton de 'or' o match 
        #para buscar un mismo campo con distintos nombres posibles en distintos formatos de imagen o versiones de EXIF.
        def prueba_otro_en_Info(*keys):
            for k in keys:
                if k in info and info[k] not in (None, "", b""):
                    return info[k]
            return None

        # aqui intento recuperarlo de exif primero sino en info
        fecha = (
            exif.get("DateTimeOriginal")
            or exif.get("DateTimeDigitized")
            or exif.get("DateTime")
            or prueba_otro_en_Info("date:create", "creation_time", "Creation Time")
        )
        marca = exif.get("Make")
        modelo = exif.get("Model")
        camara = " ".join([x for x in [marca, modelo] if x]) if (marca or modelo) else None

        campos = {
            "Fecha captura": fecha,
            "Cámara": camara,
            "Lente": exif.get("LensModel"),
            "Software": exif.get("Software") or prueba_otro_en_Info("software", "Software"),
            "Autor": exif.get("Artist") or prueba_otro_en_Info("Author", "author", "creator"),
            "Copyright": exif.get("Copyright"),
            "Orientación": exif.get("Orientation"),
            "GPS": self._extraer_gps_bonito(exif),
        }
        
        return {k: v for k, v in campos.items() if v not in (None, "", b"")}

    def analizar_un_archivo(self, archivo):
        if not os.path.isfile(archivo):
            return {"archivo": archivo, "error": "No existe o no es un archivo."}

        if not self._es_soportado(archivo):
            return {"archivo": archivo, "error": "Formato no soportado."}

        try:
            with Image.open(archivo) as im:
                metadatos = {
                    "archivo": archivo,
                    "formato": im.format,
                    "modo": im.mode,
                    "tamano": f"{im.width}x{im.height}",
                    "fechas": self._fechas_archivo(archivo),
                    "info": dict(im.info) if im.info else {},
                    "exif": {},
                }

                if im.format in ("JPEG", "JPG"):
                    metadatos["exif"] = self._extraer_exif(im)
                elif im.format in ("PNG", "GIF", "BMP"):
                    # Estos formatos no me garantizan EXIF estandar.
                    # Se muestran metadatos disponibles en el attr info.
                    metadatos["exif"] = self._extraer_exif(im)

                return metadatos
        except Exception as e:
            return {"archivo": archivo, "error": f"No se pudo analizar: {e}"}

    def salida(self, metadatos):
        print("-----------------------------------------------")
        print(f"Archivo: {metadatos.get('archivo')}")

        if "error" in metadatos:
            print(f"Error: {metadatos['error']}")
            return

        print(f"Formato: {metadatos.get('formato')}")
        print(f"Modo: {metadatos.get('modo')}")
        print(f"Tamaño: {metadatos.get('tamano')}")

        fechas = metadatos.get("fechas", {})
        if fechas:
            print(f"Creado (FS): {fechas.get('created')}")
            print(f"Modificado (FS): {fechas.get('modified')}")

        bonitos = self._campos_clave_bonitos(metadatos)
        print("\nCampos clave:")
        if bonitos:
            for k, v in bonitos.items():
                print(f"  - {k}: {self._formatear_valor(v)}")
        else:
            print("  (sin campos clave disponibles)")

        info = metadatos.get("info", {})
        print("\nMetadatos del archivo (info):")
        if info:
            for k, v in info.items():
                print(f"  - {k}: {self._formatear_valor(v)}")
        else:
            print("  (sin datos)")

        exif = metadatos.get("exif", {})
        print("\nEXIF:")
        if exif:
            for k, v in exif.items():
                print(f"  - {k}: {self._formatear_valor(v)}")
        else:
            print("  (sin EXIF disponible)")
        print("-----------------------------------------------")

    def analizar(self):
        for archivo in self.archivos:
            metadatos = self.analizar_un_archivo(archivo)
            self.salida(metadatos)

if __name__ == "__main__":
    args = arg_parser()
    scorpion = Scorpion(args)
    scorpion.analizar()

    
