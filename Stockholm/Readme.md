# Stockholm

Stockholm es una simulacion educativa de ransomware creada para la Piscina de Ciberseguridad de 42.
Demuestra cifrado hibrido con RSA + AES y procesamiento controlado de archivos dentro de un entorno de laboratorio.

Este proyecto es solo para aprendizaje y pruebas.
No lo ejecutes en carpetas personales, sistemas compartidos ni entornos de produccion.

## Objetivo Del Proyecto

El programa escanea un directorio objetivo, cifra archivos con extensiones seleccionadas y los renombra con una extension personalizada.
Tambien puede revertir la operacion si se proporciona la clave privada RSA y la contrasena correcta.

Objetivos principales:
- Entender patrones modernos de criptografia hibrida.
- Practicar flujos de analisis de malware de forma segura en entornos aislados.
- Construir herramientas CLI con banderas operativas claras.

## Como Funciona

Flujo de cifrado:
1. Genera un par de claves RSA.
2. Genera una clave de sesion AES aleatoria para cada archivo.
3. Cifra el contenido del archivo con AES-GCM.
4. Cifra la clave AES usando la clave publica RSA.
5. Guarda clave cifrada + nonce + tag + ciphertext en un nuevo archivo con extension .ft.

Flujo de descifrado:
1. Carga la clave privada RSA.
2. Descifra la clave AES de cada archivo.
3. Valida y descifra el contenido con AES-GCM.
4. Restaura el archivo original eliminando el sufijo .ft.

## Valores Por Defecto En Ejecucion

- Ruta de infeccion por defecto: /home/infection
- Extension de salida tras cifrado: .ft
- Directorio de salida de claves: /home/
- Dependencia de Python: pycryptodomex

Archivos generados:
- KEY_Stockholm_KEY.pem
- PUBLIC_KEY_Stockholm_PUBLIC_KEY.pem

## Opciones De Linea De Comandos

Ejecucion con Python:

python3 Stockholm.py [opciones]

Banderas soportadas:
- -v o --version: muestra ayuda del parser y salida de version.
- -r o --reverse: modo reversa. Acepta uno o dos valores.
- -s o --silent: reduce la salida en pantalla durante las operaciones.

Ejemplos de modo reversa:

python3 Stockholm.py -r /home/KEY_Stockholm_KEY.pem
python3 Stockholm.py -r /home/KEY_Stockholm_KEY.pem tu_contrasena_rsa

## Configuracion Local

1. Crea un entorno virtual.
2. Instala las dependencias.
3. Prepara una carpeta de pruebas.
4. Ejecuta Stockholm solo contra archivos desechables.

Ejemplo:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p /home/infection
cp infection/lol.txt /home/infection/
python3 Stockholm.py

## Flujo Con Docker

El Makefile encapsula el ciclo de vida del contenedor.

- make build: construye imagenes.
- make run: levanta el contenedor en segundo plano.
- make sh: abre una shell dentro del contenedor.
- make clean: detiene y elimina servicios en ejecucion.
- make fclean: elimina servicios e imagen.

## Notas De Seguridad

- Usa este proyecto solo en entornos de laboratorio aislados.
- No apuntes default_route a directorios sensibles.
- Haz copia de seguridad de tus archivos de prueba antes de cifrar.
- Almacena de forma segura las claves privadas generadas.
- Si la clave o contrasena es incorrecta, el descifrado fallara.

## Limitaciones Conocidas

- default_route esta hardcodeada en el codigo.
- La lista de extensiones objetivo es estatica.
- El manejo de argumentos en reversa es posicional y minimo.
- La salida de logs mezcla ingles y espanol.

## Mejoras Sugeridas

- Agregar argumento configurable para ruta de entrada.
- Agregar modo dry-run para previsualizar archivos afectados.
- Mejorar logging estructurado.
- Agregar pruebas unitarias para rutinas de cifrado y descifrado.
- Agregar verificacion de checksum antes y despues de operar.

## Estructura Del Proyecto

- Stockholm.py: punto de entrada CLI y flujo de escaneo/cifrado/descifrado.
- krypt.py: gestion de claves RSA/AES y operaciones criptograficas.
- requirements.txt: dependencias de Python.
- Makefile, Dockerfile, docker-compose.yml: ejecucion contenerizada.
- infection/: datos de ejemplo locales y referencia de extensiones.

## Recordatorio Final

Este repositorio demuestra conceptos de seguridad y simulacion ofensiva controlada.
Usalo de forma responsable, en entornos legales, y solo con fines educativos.
