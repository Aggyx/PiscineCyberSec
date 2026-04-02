#!/usr/bin/env python3
"""
arp_anomaly.py — Rate-based anomaly detection.
Detects ARP floods, gratuitous ARPs, and unsolicited replies.
"""

from scapy.all import ARP, Ether, sniff
from collections import defaultdict
from datetime import datetime
import time

FLOOD_THRESHOLD = 20    # ARPs per second per host before alerting
WINDOW_SECONDS  = 5     # sliding window

class ARPAnomalyDetector:
    def __init__(self):
        self.counts     = defaultdict(list)   # MAC → [timestamps]
        self.requests   = {}                  # (src_ip, dst_ip) → timestamp
        self.anomalies  = []

    def record(self, pkt):
        if not pkt.haslayer(ARP):
            return

        arp    = pkt[ARP]
        now    = time.time()
        src_ip = arp.psrc
        src_mac= arp.hwsrc
        dst_ip = arp.pdst

        # Prune old entries outside sliding window
        self.counts[src_mac] = [
            t for t in self.counts[src_mac] if now - t < WINDOW_SECONDS
        ]
        self.counts[src_mac].append(now)

        rate = len(self.counts[src_mac]) / WINDOW_SECONDS

        # Detection 1: ARP flood
        if rate > FLOOD_THRESHOLD:
            self._alert("ARP_FLOOD", src_mac, src_ip,
                        f"Rate: {rate:.1f}/sec (threshold {FLOOD_THRESHOLD})")

        # Detection 2: Unsolicited reply (reply with no prior matching request)
        if arp.op == 2:  # reply
            req_key = (dst_ip, src_ip)  # who would have asked?
            if req_key not in self.requests:
                self._alert("UNSOLICITED_REPLY", src_mac, src_ip,
                            f"Reply for {dst_ip}→{src_ip} without prior request")
            else:
                del self.requests[req_key]

        # Detection 3: Gratuitous ARP (src_ip == dst_ip)
        if arp.op == 1 and src_ip == dst_ip:
            self._alert("GRATUITOUS_ARP", src_mac, src_ip,
                        f"Gratuitous ARP for {src_ip}")

        # Track requests for unsolicited reply detection
        if arp.op == 1:
            self.requests[(src_ip, dst_ip)] = now

    def _alert(self, alert_type, mac, ip, detail):
        ts = datetime.now().isoformat()
        msg = f"[{ts}] {alert_type} | MAC:{mac} IP:{ip} | {detail}"
        print(f"\033[93m{msg}\033[0m")
        self.anomalies.append({"time": ts, "type": alert_type,
                               "mac": mac, "ip": ip, "detail": detail})

detector = ARPAnomalyDetector()
print("[*] Anomaly detector running...\n")
sniff(filter="arp", prn=detector.record, store=False)