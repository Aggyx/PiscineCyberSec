import requests
import argparse
import os
from bs4 import BeautifulSoup, Tag, NavigableString
from urllib.parse import urljoin, urlparse, urldefrag

class ErrorDeEntrada(Exception):
    def __init__(self, mensaje="Entrada incorrecta"):
        self.mensaje = mensaje
        super().__init__(mensaje)

    def __str__(self):
        return self.mensaje

def arg_parser():
    try:
        argv_parser = argparse.ArgumentParser(prog='Spider',description='./spider [-rlp] URL\nSpider es un programa que descarga las imagenes de la URL.', epilog='Piscina Cyberseguridad - smagniny')
        argv_parser.add_argument('-r', help='Descarga recursivamente las imagenes de una URL', action='store_true')
        argv_parser.add_argument('-l', help='Indica la profundidad máxima de la descarga recursiva, 5 por defecto', default=5,  type=int)
        argv_parser.add_argument('-p', help='Indica la ruta de almacenamiento de las imagenes descargadas, ./data/ por defecto', default='./data/', type=str)
        argv_parser.add_argument('URL', help='Indica la URL a scrapear', type=str)
        argv = argv_parser.parse_args()

        if argv.l != 5 and argv.r == False:
            raise ErrorDeEntrada("Entrada incorrecta, especifica -r para usar -l")
        return argv.r, argv.l, argv.p, argv.URL
    except Exception as E:
        print(str(E))

class Spider(BeautifulSoup):
    '''
    Spider para recuperar html y parsearlo, e incrementar el array de url de imagenes.

    https://www.crummy.com/software/BeautifulSoup/bs4/doc/#specifying-the-parser-to-use
    '''

    def __init__(self, url="", recursividad=False, profundidad=5, ruta_de_almacenamiento="./data/"):
        self.parse_url(url)

        self.__recursividad             = recursividad
        self.__profundidad              = profundidad
        self.__ruta_de_almacenamiento   = ruta_de_almacenamiento

        self.array_de_imagenes          = []
        self._imagenes_vistas           = set()
        self._paginas_visitadas         = set()
        self.respuesta                  = None
        self.sopa_de_letras             = None
        self.html                       = None

        print(f"url: ", self.__url)
        print(f"dominio: ", self.__fulldomain)
        print(f"subdominio: ", self.__subdomain)
        print(f"extension: ", self.__ext)

        self.dame_la_pagina_del_servidor(self.__url)

    def set_url(self, param):
        self.__url = param

    def set_recursividad(self, param):
        self.__recursividad = param

    def set_profundidad(self, param):
        self.__profundidad = param

    def set_ruta_de_almacenamiento(self, param):
        self.__ruta_de_almacenamiento = param
    
    @property
    def set_url(self):
        return self.__url

    @property
    def get_recursividad(self):
        return self.__recursividad

    @property
    def get_profundidad(self):
        return self.__profundidad

    @property    
    def get_ruta_de_almacenamiento(self):
        return self.__ruta_de_almacenamiento
    
    def parse_url(self, url):
        # https://www.lol.com/
        self.__url = url
        if self.__url[-1] == '/':
            self.__url = self.__url[:len(self.__url)-1]

        url_slash_split = url.split("/")
        self.__https      = True if url_slash_split[0].count('s') else False
        self.__fulldomain = url_slash_split[2] if len(url_slash_split) >=2 else None

        domain_dot_split = self.__fulldomain.split(".")

        self.__subdomain = domain_dot_split[0] if len(domain_dot_split) >= 1 else None
        self.__domain    = domain_dot_split[1] if len(domain_dot_split) >= 2 else None
        self.__ext       = domain_dot_split[2] if len(domain_dot_split) >= 3 else None

        if self.__fulldomain is None:
            raise ErrorDeEntrada("URL inválida: No se puede determinar el dominio (comprueba los '/')")

    def dame_la_pagina_del_servidor(self, url, profundidad=0):
        '''
        Hace la petición al servidor de la página deseada.
        Guardando la respuesta y el contenido (body).
        '''
        url_limpia, _ = urldefrag(url) # _ es el contenido frontend que no me interesa, como #section1 o cosas así

        if profundidad > self.__profundidad:
            print("\n\nHemos llegado al limíte de profundidad. \n\n")
            return

        if url_limpia in self._paginas_visitadas:
            return

        self._paginas_visitadas.add(url_limpia)

        try:
            self.respuesta = requests.get(url_limpia, timeout=15)
            self.respuesta.raise_for_status()
        except requests.RequestException as e:
            print(f"Error al pedir {url_limpia}: {e}")
            return

        print(self.respuesta.ok)

        content_type = self.respuesta.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            return

        self.sopa_de_letras = self.respuesta._content
        self.parsea_la_pagina_spider(url_limpia, profundidad)
        
    def parsea_la_pagina_spider(self, base_url, profundidad):
        '''
        Esta función la uso para interpretar la respuesta en formato HTML
        Permite encontrar los tags interesantes a través de los objetos de BeautifulSoup
        '''
        self.html = BeautifulSoup(self.sopa_de_letras, 'html.parser')

        self.extrae_imagenes_spider(self.html, base_url, profundidad)
        self.descarga_imagenes()

    def extrae_imagenes_spider(self, html, base_url, profundidad):
        '''
        Esta función extrae los tags html que renderizan una imagen.
        '''
        def selecionar_archivo_del_tipo_q_guste(archivo):
            if not archivo:
                return False

            aceptados = (".jpg", ".jpeg", ".png", ".gif", ".bmp")
            path = urlparse(archivo).path.lower()
            return any(path.endswith(ext) for ext in aceptados)

        def es_link_navegable(archivo):
            if not archivo:
                return False
            archivo = archivo.strip().lower()
            return not (archivo.startswith("#")
                or archivo.startswith("mailto:")
                or archivo.startswith("javascript:"))

        def es_mismo_dominio(url):
            netloc = urlparse(url).netloc
            return netloc == self.__fulldomain

        # Ya no uso esta funci'on
        def extraer_attr(un_attr, link):
            '''
            getattr no me funciona sobre NavigableString o algunos Tags?
            no voy a complicarme y hacerlo con match ya que busco por attr.
            '''
            match un_attr:
                case "href":
                    return link.href
                case "src":
                    return link.src

        def lambdaa(un_tag_mio, un_attr_mio):
            def tiene_attr(tag):
                if not isinstance(tag, Tag):
                    return False
                return (tag.name == un_tag_mio and tag.has_attr(un_attr_mio))
            return tiene_attr

        tags_por_buscar = ["img", "a"]                                             
        attr_por_buscar =  {
            "img": ("src",),
            "a": ("href",),
        }
        # ... Esto quisiera añadir más tags y attributos como picture o meta
        for un_tag in tags_por_buscar:
            for un_attr in attr_por_buscar[un_tag]:
                print(f"Probando buscar <{un_tag} attr={un_attr}> ")
                res = html.find_all(lambdaa(un_tag, un_attr))
                #print(len(res))
                for link in res:
                    res = link.get(un_attr)
                    #print(res)
                    if not res:
                        continue

                    url_absoluta = urljoin(base_url, res)
                    url_absoluta, _ = urldefrag(url_absoluta)

                    if selecionar_archivo_del_tipo_q_guste(url_absoluta):
                        if url_absoluta not in self._imagenes_vistas:
                            self.array_de_imagenes.append(url_absoluta)
                            self._imagenes_vistas.add(url_absoluta)
                    elif self.__recursividad and un_tag == "a" and es_link_navegable(res) and es_mismo_dominio(url_absoluta):
                        self.dame_la_pagina_del_servidor(url_absoluta, profundidad + 1)
        print(self.array_de_imagenes)

    def descarga_imagenes(self):
        os.makedirs(self.__ruta_de_almacenamiento, exist_ok=True)

        while self.array_de_imagenes:
            image_url = self.array_de_imagenes.pop(-1)
            print("Descargando imagen: ", f"{image_url}\n")

            try:
                image_response = requests.get(image_url, stream=True, timeout=15)
                image_response.raise_for_status()
            except requests.RequestException as e:
                print(f"No se pudo descargar {image_url}: {e}")
                continue

            content_type = image_response.headers.get("Content-Type", "").lower()
            if not content_type.startswith("image/"):
                print(f"Saltando recurso no-imagen: {image_url} ({content_type})")
                continue

            nombre = os.path.basename(urlparse(image_url).path) or "imagen_sin_nombre"
            nombre = nombre.replace("/", "_")
            destino = os.path.join(self.__ruta_de_almacenamiento, nombre)

            with open(destino, 'wb') as fd: #Docs de requests
                for chunk in image_response.iter_content(chunk_size=4096):
                    fd.write(chunk)

if __name__ == "__main__":
    r_flag, l_flag, p_flag, url_param = arg_parser()
    print("Flag de recusividad: ", r_flag)
    print("Flag de profundidad: ", l_flag)
    print("Flag de almacenamiento: ", p_flag)

    spider = Spider(url_param, r_flag, l_flag, p_flag)





    

