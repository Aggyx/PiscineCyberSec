# Inquisitor (Address Resolution Protocol Exploits)

Inquisitor es un wrapper de Scapy que permite construir solicitudes y respuestas de paquetes ARP para realizar un ARP spoof. Permite también envenamiento(poisoning) que mantiene el spoof a través del tiempo.

Una vez las tablas ARP han sido comprometidas Inquisitor puede monitorizar el tráfico entre victima y el router, realizando un ataque de ManInTheMiddle (MITM).

El wrapper esta programado para que se use como CLI para un uso más granular. Igualmente le he puesto funciones que hacen el ataque directamente.


# Docker setup
Uso docker ccomo laboratorio de pruebas para simular la red, clientes, servidores y la máquina atacante.

topología de red del ejercicio:
  ftp_server  (172.20.0.10) - servidor FTP (vsftpd)
  client      (172.20.0.20) - sesión cliente FTP
  attacker    (172.20.0.99) - atacante a través proto ARP.
  Network:    arp_lab / 172.20.0.0/24 - mascara /24  -> 254 Hosts

Uso de la directiva cap_add en los servicios docker:
    **NET_RAW**: Otorga permiso para crear **sockets crudos** (del inglés *raw sockets*).
        Un socket crudo es un tipo de socket de red que permite al programa construir
        y enviar paquetes manualmente, byte a byte, sin que el sistema operativo
        intervenga en la construcción de las cabeceras (Ethernet, IP, ARP...).
        En un socket normal (como el que usa un navegador web), el SO construye
        automáticamente las cabeceras de red; con un socket crudo, el programador
        las controla por completo.
        Scapy necesita este permiso para dos cosas:
        - Construir y enviar tramas ARP falsificadas con MACs arbitrarias
        - Escuchar todo el tráfico de la interfaz a nivel de trama Ethernet
        (no solo el dirigido a nuestra IP), lo que se conoce como **modo promiscuo**
    ----------------------------------------------------------------------------------
    **NET_ADMIN**: Otorga permiso para realizar **configuraciones de red avanzadas** dentro del contenedor. 
    Incluye operaciones como:
    - Modificar interfaces de red (activar/desactivar, cambiar MTU)
    - Gestionar tablas de enrutamiento (*routing tables*)
    - Manipular la tabla ARP del propio sistema
    - Activar el **reenvío de paquetes IP** (*IP forwarding*), que es la
    capacidad de que el contenedor actúe como enrutador intermedio,
    recibiendo paquetes destinados a otra IP y redirigiéndolos hacia
    su destino real — imprescindible para el ataque MitM sin cortar
    la conectividad de la víctima

Solo el contenedor atacante necesita NET_ADMIN. El servidor FTP y el
cliente únicamente necesitan conectividad de red estándar.

# Pruebas 

## Flujo rapido con Make

1. Levantar laboratorio:

```bash
make
```

2. En una terminal, arrancar atacante escuchando (ARP poison + sniff TCP):

```bash
make inquisitor
```

3. En otra terminal, simular trafico FTP desde cliente:

```bash
make lab-test
```

## Comandos manuales en cliente FTP

Entrar al contenedor cliente:

```bash
make client-sh
```

Abrir sesion FTP y simular login:

```bash
ftp 172.20.0.10 21
Name: labuser
Password: 42isTheAnswer
ls
pwd
quit
```

Simular envio y descarga de archivos:

```bash
echo "mensaje de prueba ARP" > /tmp/lab_file.txt
ftp 172.20.0.10 21
Name: labuser
Password: 42isTheAnswer
put /tmp/lab_file.txt lab_file.txt
get lab_file.txt /tmp/lab_file_downloaded.txt
ls
quit
```

Comandos no interactivos equivalentes:

```bash
make ftp-login
make ftp-transfer
```