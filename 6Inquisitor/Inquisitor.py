'''
Bidirectional ARP Poisoning
'''
import argparse
import ipv4
import scapy.all as scapy

def arg_parser():
    try:
        argv_parser = argparse.ArgumentParser(
            prog="Inquisitor",
            description='./Inquisitor A program that performs a bidirectional ARP poisoning attack on a victim and a gateway',
            epilog='Piscina Cyberseguridad - smagniny',
        )
        argv_parser.add_argument('IP_SOURCE', help='The source IP of the sender of the attack', action='store')
        argv_parser.add_argument('MAC_SOURCE', help='The source MAC of the sender of the attack', action='store')
        argv_parser.add_argument('IP_TARGET', help='The destination IP of the attack ', action='store')
        argv_parser.add_argument('MAC_TARGET', help='The destination MAC of the attack ', action='store')

        argv = argv_parser.parse_args()

        if not argv.IP_SOURCE or not argv.MAC_SOURCE or not argv.IP_TARGET or not argv.MAC_TARGET:
            raise Exception("All arguments are required")

        return argv.IP_SOURCE, argv.MAC_SOURCE, argv.IP_TARGET, argv.MAC_TARGET
    except Exception as E:
        print(str(E))
        return False, False, False, False

class Inquisitor(scapy):
    def __init__(self, victim_ip, victim_mac, gateway_ip, gateway_mac):
        self.victim_ip = victim_ip if self.ensure_ipv4(victim_ip) else raise Exception("Invalid victim IP address")
        self.victim_mac = victim_mac
        self.gateway_ip = gateway_ip if self.ensure_ipv4(gateway_ip) else raise Exception("Invalid gateway IP address")
        self.gateway_mac = gateway_mac

        print(f"Victim IP: {victim_ip}, Victim MAC: {victim_mac}")
        print(f"Gateway IP: {gateway_ip}, Gateway MAC: {gateway_mac}")

    def ensure_ipv4(self, ip: str):
        '''
        Ensure that the given IP address is a valid IPv4 address
        '''
        splitted = ip.split('.')
        if len(splitted) != 4:
            return False
        for octet in splitted:
            if not octet.isdigit() or int(octet) < 0 or int(octet) > 255:
                return False
        return True

    def get_mac(self, ip):
        '''
        Get the MAC address of the given IP address
        '''
        pass

    def poison(self):
        '''
        Poison the ARP cache of the victim and the gateway
        '''
        pass

    def restore(self):
        '''
        Restore the ARP cache of the victim and the gateway
        '''
        pass

if __name__ == "__main__":
    victim_ip, victim_mac, gateway_ip, gateway_mac = arg_parser()
    #inquisitor = Inquisitor(victim_ip, victim_mac, gateway_ip, gateway_mac)
    #inquisitor.poison()
    # Wait for the user to stop the attack
    #input("Press Enter to stop the attack...")
    #inquisitor.restore()