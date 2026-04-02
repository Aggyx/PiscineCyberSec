#!/usr/bin/env python3
"""
arp_sniffer.py — Passively monitors ARP traffic on the segment.
Run on the attacker or a monitoring host with a SPAN port.
"""

from scapy.all import ARP, sniff, Ether
from datetime import datetime
import json
import logging

logging.basicConfig(
    filename="arp_monitor.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# Trusted IP→MAC database (populate from DHCP logs / known inventory)
TRUSTED_MAP = {
    "172.20.0.10": "de:ad:be:ef:10:10",  # ftp_server (update after docker inspect)
    "172.20.0.20": "de:ad:be:ef:20:20",  # client
}

arp_table = {}  # learned IP→MAC during session

def analyze_arp(pkt):
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    src_ip  = arp.psrc
    src_mac = arp.hwsrc
    op      = "REQUEST" if arp.op == 1 else "REPLY"
    ts      = datetime.now().isoformat()

    print(f"[{ts}] ARP {op}: {src_ip} → {src_mac}")

    if arp.op == 2:  # Only analyze replies
        # Check 1: Does MAC match our trusted database?
        if src_ip in TRUSTED_MAP:
            if TRUSTED_MAP[src_ip].lower() != src_mac.lower():
                alert = (
                    f"ALERT: IP {src_ip} was MAC {TRUSTED_MAP[src_ip]}, "
                    f"now claiming {src_mac} — possible ARP spoofing!"
                )
                print(f"\033[91m{alert}\033[0m")
                logging.warning(alert)

        # Check 2: Has this IP appeared before with a different MAC?
        if src_ip in arp_table:
            prev_mac = arp_table[src_ip]
            if prev_mac.lower() != src_mac.lower():
                alert = (
                    f"ALERT: MAC change detected for {src_ip}: "
                    f"{prev_mac} → {src_mac}"
                )
                print(f"\033[91m{alert}\033[0m")
                logging.warning(alert)

        arp_table[src_ip] = src_mac

print("[*] ARP sniffer running. Press Ctrl+C to stop.\n")
sniff(filter="arp", prn=analyze_arp, store=False)