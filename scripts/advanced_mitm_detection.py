import os
import socket
import subprocess
import pandas as pd
from collections import defaultdict, Counter
from scapy.all import rdpcap, IP, TCP, UDP, ARP

# Get domain name from IP (reverse DNS)
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Block a suspicious IP using Windows Firewall
def block_ip(ip):
    command = f'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'
    try:
        subprocess.run(["powershell", "-Command", command], check=True)
        print(f"[INFO] Blocked suspicious IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[ERROR] Failed to block IP: {ip}")

# Extract traffic data for inspection
def extract_traffic_data(pcap_path):
    packets = rdpcap(pcap_path)
    traffic_data = []
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            packet_size = len(pkt)
            traffic_data.append([src_ip, dst_ip, protocol, packet_size])
    df = pd.DataFrame(traffic_data, columns=["Source_IP", "Destination_IP", "Protocol", "Packet_Size"])
    return df, packets

# Detect possible ARP spoofing
def detect_arp_spoofing(packets):
    mac_table = {}
    alerts = []
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in mac_table and mac_table[ip] != mac:
                alerts.append(f"[ALERT] ARP Spoofing Detected: {ip} has multiple MACs: {mac_table[ip]} vs {mac}")
            mac_table[ip] = mac
    return alerts

# High-volume traffic detector (can be part of MITM)
def detect_suspicious_traffic(df):
    alerts = []
    src_ip_counts = Counter(df["Source_IP"])
    for ip, count in src_ip_counts.items():
        if count > 100:
            alert = f"[WARNING] Suspicious traffic volume from {ip} — {count} packets"
            alerts.append(alert)
            block_ip(ip)
    return alerts

# Combined MITM Detection Function
def detect_mitm_attacks(pcap_path, output_csv="data/processed/network_monitoring_analysis.csv"):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    print("[INFO] Reading pcap file for analysis...")
    df, packets = extract_traffic_data(pcap_path)
    df.to_csv(output_csv, index=False)
    print(f"[INFO] Traffic data saved to {output_csv}")

    print("\n[STEP 1] Detecting ARP Spoofing...")
    arp_alerts = detect_arp_spoofing(packets)
    for alert in arp_alerts:
        print(alert)

    print("\n[STEP 2] Analyzing Traffic Volume...")
    volume_alerts = detect_suspicious_traffic(df)
    for alert in volume_alerts:
        print(alert)

    print("\n[INFO] MITM Detection complete. Analysis done.")

if __name__ == "__main__":
    pcap_path = "data/raw/evidence02.pcap"  # Update path if needed
    detect_mitm_attacks(pcap_path)
