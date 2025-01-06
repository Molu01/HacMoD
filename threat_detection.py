import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from sklearn.ensemble import IsolationForest
import pandas as pd
import datetime

# Initialize a list to store packet details
data = []

def capture_packet(packet):
    """
    Captures and processes packets, extracting features for analysis.
    """
    try:
        if packet.haslayer(HTTPRequest):
            timestamp = datetime.datetime.now()
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            http_method = packet[HTTPRequest].Method.decode()
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()

            # Extracting packet features
            packet_data = {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'http_method': http_method,
                'url': url
            }
            data.append(packet_data)
            print(f"[Captured] {packet_data}")
    except Exception as e:
        print(f"[Error] Failed to process packet: {e}")

def start_sniffing(interface):
    """
    Starts packet sniffing on the specified network interface.
    """
    print(f"[INFO] Starting packet capture on interface {interface}...")
    try:
        scapy.sniff(iface=interface, filter="tcp port 80", prn=capture_packet, store=False)
    except PermissionError:
        print("[ERROR] Please run the script with administrative privileges.")
    except Exception as e:
        print(f"[ERROR] Unable to sniff packets: {e}")

def analyze_data():
    """
    Analyzes captured data for anomalies.
    """
    print("[INFO] Analyzing captured data...")

    if not data:
        print("[WARNING] No data captured for analysis.")
        return

    # Convert captured data to a pandas DataFrame
    df = pd.DataFrame(data)

    # Feature engineering
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['source_ip_encoded'] = pd.factorize(df['source_ip'])[0]
    df['destination_ip_encoded'] = pd.factorize(df['destination_ip'])[0]
    df['url_encoded'] = pd.factorize(df['url'])[0]

    # Select features for anomaly detection
    feature_columns = ['source_ip_encoded', 'destination_ip_encoded', 'hour']
    feature_data = df[feature_columns]

    # Isolation Forest for anomaly detection
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(feature_data)
    df['anomaly_score'] = model.decision_function(feature_data)
    df['is_anomaly'] = model.predict(feature_data) == -1

    # Output anomalies
    anomalies = df[df['is_anomaly']]
    print(f"[INFO] Detected {len(anomalies)} anomalies:")
    print(anomalies[['timestamp', 'source_ip', 'destination_ip', 'url']])

if __name__ == "__main__":
    interface = input("Enter your network interface (e.g., en0, en1): ").strip()
    try:
        start_sniffing(interface)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping packet capture and analyzing data...")
        analyze_data()
