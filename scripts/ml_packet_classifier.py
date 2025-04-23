from scapy.all import rdpcap, IP
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Extract features from pcap packets for ML classification
def extract_features(packets):
    data, labels = [], []
    for pkt in packets:
        length = len(pkt)
        layers = len(pkt.layers())
        proto_name = pkt.payload.name if hasattr(pkt, "payload") else "None"
        proto_num = {"IP": 1, "ARP": 2, "Ethernet": 3, "IPv6": 4}.get(proto_name, 0)
        raw = sum(bytes(pkt)[:20]) if len(pkt) >= 20 else 0
        label = 1 if IP in pkt else 0  # IP = 1 (normal), others = 0
        data.append([length, layers, proto_num, raw])
        labels.append(label)
    return np.array(data), np.array(labels)

# Train a Random Forest classifier to recognize IP packets
def train_packet_classifier(pcap_path="data/raw/evidence03.pcap", model_output="models/rf_ip_classifier.pkl"):
    print(f"Reading packets from: {pcap_path}")
    packets = rdpcap(pcap_path)

    print("Extracting features...")
    X, y = extract_features(packets)
    os.makedirs("data/labeled", exist_ok=True)
    pd.DataFrame(X, columns=["Length", "Layers", "Protocol", "ByteSum"]).to_csv("data/labeled/ip_packet_features.csv", index=False)
    print("Feature CSV saved at: data/labeled/ip_packet_features.csv")

    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    print("Training Random Forest model...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    print("\nClassification Report:")
    print(classification_report(y_test, clf.predict(X_test)))

    os.makedirs(os.path.dirname(model_output), exist_ok=True)
    joblib.dump(clf, model_output)
    print(f"Model saved to: {model_output}")

if __name__ == "__main__":
    train_packet_classifier()
