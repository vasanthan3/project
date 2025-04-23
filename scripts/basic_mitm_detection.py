import os
import socket
import pandas as pd
from scapy.all import rdpcap, IP, ARP
from collections import defaultdict

def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def detect_arp_mitm(packets):
    ip_mac_map = {}
    spoof_alerts = []

    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in ip_mac_map and ip_mac_map[ip] != mac:
                spoof_alerts.append(f"Possible ARP Spoofing: {ip} -> {ip_mac_map[ip]} vs {mac}")
            ip_mac_map[ip] = mac

    return spoof_alerts

def detect_generic_mitm_anomalies(packets):
    conn_tracker = defaultdict(int)
    for pkt in packets:
        if IP in pkt:
            conn = (pkt[IP].src, pkt[IP].dst)
            conn_tracker[conn] += 1

    for conn, count in conn_tracker.items():
        if count > 100:
            print(f"High volume traffic detected: {conn} - {count} packets (Possible MITM)")

def mitm_analyzer(pcap_path):
    print(f"\nReading packets from: {pcap_path}")
    packets = rdpcap(pcap_path)

    print("\nDetecting ARP spoofing...")
    arp_alerts = detect_arp_mitm(packets)
    for alert in arp_alerts:
        print(alert)

    print("\nAnalyzing for abnormal traffic patterns...")
    detect_generic_mitm_anomalies(packets)

    print("\nMITM Analysis complete.")

if __name__ == "__main__":
    pcap_file = "data/raw/evidence02.pcap"
    mitm_analyzer(pcap_file)
