import time
import os
from sqlalchemy import create_engine
import requests
import joblib
import psycopg2
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load model and encoders
model_package = joblib.load('ddos_detection_model.pkl')
model = model_package['model']
label_encoders = model_package['label_encoders']

# Define columns to drop (must match training)
columns_to_drop = [
    'timestamp', 'type', 'agent_ip', 'inputport', 'outputport', 'src_mac',
    'dst_mac', 'ethernet_type', 'in_vlan', 'out_vlan', 'flow_id', 'datapath_id',
    'abuseipdb_usage_type', 'dst_ip'
]

# Load configuration from environment variables
MITIGATOR_API_PORT = os.getenv('MITIGATOR_API_PORT')
MITIGATOR_HOST = os.getenv('MITIGATOR_HOST')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_PORT = int(os.getenv('DB_PORT'))

TABLE_NAME = os.getenv('DB_TABLE')

# Query TimescaleDB for the last 10 seconds
def fetch_latest_flows():
    """Fetch latest flows from database."""
    engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    query = f"""
        SELECT * FROM {TABLE_NAME}
        WHERE timestamp >= NOW() - INTERVAL '10 seconds';
    """
    df = pd.read_sql_query(query, engine)
    engine.dispose()
    return df

# Send mitigation request
def announce_ip(ip):
    """Announce to mitigator via API malicious source IP Addresses."""
    try:
        response = requests.post(
            f"http://{MITIGATOR_HOST}:{MITIGATOR_API_PORT}/announce",
            json={'ip': ip}  # send JSON instead of form data
        )
        if response.status_code == 200:
            print(f"Mitigation announced for {ip}")
        else:
            print(f"Failed to announce mitigation for {ip}, status: {response.status_code}, response: {response.text}")
    except Exception as e:
        print(f"Error announcing mitigation: {e}")

# Preprocess flows
def preprocess_flows(df):
    """Function to process the queried flows."""
    df = df.copy()
    if 'src_ip' not in df.columns:
        raise ValueError("Missing 'src_ip' column for reporting.")

    src_ips = df['src_ip']

    # Make sure to drop src_ip as well
    df = df.drop(columns=columns_to_drop + ['src_ip'], errors='ignore')

    # Apply label encoders
    for col, le in label_encoders.items():
        if col in df.columns:
            df[col] = df[col].map(lambda s: le.transform([s])[0] if s in le.classes_ else -1)

    return df, src_ips

# Real-time detection service
def detect_and_report():
    """Detection and reporting service in real-time."""
    while True:
        try:
            print("Fetching Data")
            df = fetch_latest_flows()
            if df.empty:
                time.sleep(10)
                continue

            X, src_ips = preprocess_flows(df)
            predictions = model.predict(X)

            # Get malicious IPs
            malicious_ips = src_ips[predictions == 1].unique()
            for ip in malicious_ips:
                print(f"Triggering Blackhole for Malicious Source IP: {ip}")
                announce_ip(ip)

        except Exception as e:
            print(f"Error during detection loop: {e}")

        time.sleep(10)

if __name__ == "__main__":
    detect_and_report()
