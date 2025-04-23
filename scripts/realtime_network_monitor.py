import os
import joblib
import socket
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP, ARP
from sklearn.preprocessing import MinMaxScaler
from statsmodels.tsa.arima.model import ARIMA

# -------------------------------
# 🔍 Feature Extraction & Classification
# -------------------------------
def extract_features(pkt):
    length = len(pkt)
    layers = len(pkt.layers()) if hasattr(pkt, 'layers') else 1
    proto = pkt.proto if hasattr(pkt, 'proto') else 0
    byte_sum = sum(bytes(pkt))
    return [length, layers, proto, byte_sum]

def classify_packet(pkt, model):
    if not hasattr(pkt, 'proto'):
        return None
    features = extract_features(pkt)
    df = pd.DataFrame([features], columns=["Length", "Layers", "Protocol", "ByteSum"])
    return model.predict(df)[0]

# -------------------------------
# 🌐 DDoS Detection & IP Blocking
# -------------------------------
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def block_ip(ip):
    command = f'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'
    try:
        subprocess.run(["powershell", "-Command", command], check=True)
        print(f"🚫 Blocked IP: {ip} ({get_domain(ip)})")
    except subprocess.CalledProcessError:
        print(f"⚠️ Failed to block IP: {ip}")

# -------------------------------
# 📈 Forecasting & Anomaly Detection
# -------------------------------
timestamps = []
packet_sizes = []

def detect_anomalies_live():
    df = pd.DataFrame({"Timestamp": timestamps, "Packet_Length": packet_sizes})
    mean, std = df["Packet_Length"].mean(), df["Packet_Length"].std()
    df["Anomaly"] = df["Packet_Length"].apply(lambda x: abs(x - mean) > 2 * std)
    return df[df["Anomaly"] == True]

def forecast_traffic():
    if len(packet_sizes) < 10:
        return
    df = pd.DataFrame({"Packet_Length": packet_sizes})
    scaler = MinMaxScaler()
    scaled = scaler.fit_transform(df)
    model = ARIMA(scaled, order=(3, 1, 0)).fit()
    forecasted = model.predict(start=0, end=len(df)-1)
    predicted = scaler.inverse_transform(forecasted.reshape(-1, 1)).flatten()
    print("📊 Forecast sample (next trend):", predicted[:5])

# -------------------------------
# 🛡️ Packet Processing Logic
# -------------------------------
ddos_counter = {}
arp_table = {}

def packet_handler(pkt):
    global ddos_counter, arp_table

    # Traffic & DDoS Monitoring
    if IP in pkt:
        src_ip = pkt[IP].src
        timestamps.append(float(pkt.time))
        packet_sizes.append(len(pkt))

        domain = get_domain(src_ip)
        print(f"🌐 IP: {src_ip} | Domain: {domain}")

        ddos_counter[src_ip] = ddos_counter.get(src_ip, 0) + 1
        if ddos_counter[src_ip] > 100:
            print(f"🚨 Possible DDoS from {src_ip} ({ddos_counter[src_ip]} packets)")
            block_ip(src_ip)

    # ARP Spoof Detection
    if ARP in pkt and pkt[ARP].op == 2:
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            print(f"⚠️ ARP Spoofing: {ip} has conflicting MACs {arp_table[ip]} and {mac}")
        arp_table[ip] = mac

    # ML Packet Classification
    prediction = classify_packet(pkt, packet_handler.model)
    if prediction is not None:
        print(f"🔍 Packet classified as: {'IP Packet' if prediction == 1 else 'Non-IP'}")

# -------------------------------
# 🔁 Real-Time Monitor Trigger
# -------------------------------
def full_analysis_live():
    print("📥 Loading IP packet classifier...")
    model = joblib.load("models/packet_type_classifier.pkl")
    packet_handler.model = model

    print("🔎 Starting real-time packet sniffing...")
    sniff(prn=packet_handler, store=False)

    # Visualizing Packet Size Distribution
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, packet_sizes, label="Packet Size Over Time", color='blue')
    plt.xlabel("Timestamp")
    plt.ylabel("Packet Size (Bytes)")
    plt.title("Packet Size Distribution Over Time")
    plt.legend()
    plt.grid(True)
    plt.show()

    # Displaying Traffic Data Table
    traffic_df = pd.DataFrame({
        "Timestamp": timestamps,
        "Packet_Size": packet_sizes
    })
    print("\nTraffic Data Table:")
    print(traffic_df.head())

if __name__ == "__main__":
    full_analysis_live()
