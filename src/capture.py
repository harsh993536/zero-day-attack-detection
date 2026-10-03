import time
import joblib
import pandas as pd
import os
from datetime import datetime

from scapy.all import sniff, IP

from features import Flow
from risk import calculate_risk_score, get_risk_level


# -----------------------------------
# Load trained AI components
# -----------------------------------

scaler = joblib.load("../models/scaler.pkl")
model = joblib.load("../models/isolation_forest.pkl")


# -----------------------------------
# Features used by the AI model
# -----------------------------------

FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Average Packet Size"
]


# -----------------------------------
# Store active network flows
# -----------------------------------

flows = {}


# -----------------------------------
# Process captured packet
# -----------------------------------

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    # Identify protocol
    protocol = ip.proto

    src_port = 0
    dst_port = 0

    if packet.haslayer("TCP"):
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport

    elif packet.haslayer("UDP"):
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport

    # Create flow key
    flow_key = (
        ip.src,
        ip.dst,
        src_port,
        dst_port,
        protocol
    )

    # Create a new flow
    if flow_key not in flows:

        flows[flow_key] = Flow(packet)

    else:

        flows[flow_key].update(packet)


# -----------------------------------
# Analyze flows periodically
# -----------------------------------

def analyze_flows():

    print("\n" + "=" * 60)
    print("AI REAL-TIME ANALYSIS")
    print("=" * 60)

    for flow_key, flow in list(flows.items()):

        features = flow.get_features()

        df = pd.DataFrame([features])

        df = df[FEATURE_NAMES]

        # Scale features
        X_scaled = scaler.transform(df)

        # AI prediction
        prediction = model.predict(X_scaled)[0]

        # Anomaly score
        anomaly_score = model.decision_function(X_scaled)[0]

        # Risk score
        risk_score = calculate_risk_score(anomaly_score)

        risk_level = get_risk_level(risk_score)

        status = (
            "ANOMALY"
            if prediction == -1
            else "NORMAL"
        )

        print("\nSource      :", flow_key[0])
        print("Destination :", flow_key[1])
        print("Src Port    :", flow_key[2])
        print("Dst Port    :", flow_key[3])
        print("Status      :", status)
        print("Anomaly Score:", round(anomaly_score, 4))
        print("Risk Score  :", risk_score)
        print("Risk Level  :", risk_level)

                # Save live detection result
        result = {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": flow_key[0],
            "Destination IP": flow_key[1],
            "Source Port": flow_key[2],
            "Destination Port": flow_key[3],
            "Protocol": flow_key[4],
            "Status": status,
            "Anomaly Score": round(anomaly_score, 4),
            "Risk Score": risk_score,
            "Risk Level": risk_level
        }

        output_path = "../data/processed/live_detection_results.csv"

        os.makedirs("../data/processed", exist_ok=True)

        result_df = pd.DataFrame([result])

        file_exists = os.path.exists(output_path)

        result_df.to_csv(
            output_path,
            mode="a",
            header=not file_exists,
            index=False
        )

    # Clear flows after analysis
    flows.clear()


# -----------------------------------
# Start capture
# -----------------------------------

print("\n" + "=" * 60)
print("🛡️ ZERO-DAY ATTACK DETECTION")
print("REAL-TIME BEHAVIORAL AI")
print("=" * 60)

print("\nCapturing network traffic...")
print("AI analysis will run every 10 seconds.")
print("Press CTRL+C to stop.\n")


try:

    while True:

        # Capture packets for 10 seconds
        sniff(
            prn=process_packet,
            store=False,
            timeout=10
        )

        # Analyze captured flows
        analyze_flows()


except KeyboardInterrupt:

    print("\n")
    print("Real-time detection stopped.")