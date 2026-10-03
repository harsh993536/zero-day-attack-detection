# Zero-Day Attack Detection using Behavioral AI

## 🔐 Project Overview

Zero-Day Attack Detection using Behavioral AI is an AI-based cybersecurity system designed to detect suspicious and anomalous network behavior.

Instead of depending only on known attack signatures, the system learns normal network traffic behavior and identifies unusual patterns using **Machine Learning and Behavioral Anomaly Detection**.

The project supports both:

- 📊 Offline detection using the CIC-IDS2017 dataset
- 🔴 Real-time network monitoring using Scapy
- 🖥️ SOC-style monitoring dashboard using Streamlit

---

## 🎯 Objectives

- Detect unusual network behavior
- Extract behavioral features from network traffic
- Train an AI-based anomaly detection model
- Identify potentially malicious traffic
- Calculate anomaly and risk scores
- Generate high-risk alerts
- Monitor live network traffic
- Display detection results through a dashboard

---

## 🧠 System Methodology

```text
Network Traffic
      ↓
Packet Capture
      ↓
Flow Formation
      ↓
Feature Extraction
      ↓
Data Preprocessing
      ↓
StandardScaler
      ↓
Isolation Forest
      ↓
Anomaly Detection
      ↓
Risk Score
      ↓
SOC Dashboard



🔍 Behavioral Features
The system analyzes 12 network behavioral features:

Flow Duration
Total Forward Packets
Total Backward Packets
Total Length of Forward Packets
Total Length of Backward Packets
Flow Bytes/s
Flow Packets/s
Packet Length Mean
Packet Length Standard Deviation
SYN Flag Count
ACK Flag Count
Average Packet Size


🤖 Machine Learning
The main machine learning algorithm used in this project is:

Isolation Forest
Isolation Forest is an unsupervised anomaly detection algorithm that identifies observations that are significantly different from normal behavior.

The model is trained primarily using benign network traffic.

Anomaly Score
The Isolation Forest decision function produces an anomaly score.

Higher score → more normal behavior
Lower score → more anomalous behavior
⚠️ Risk Scoring
The project converts the anomaly score into a project-defined risk score from 0 to 100.

0–29    → LOW
30–69   → MEDIUM
70–100  → HIGH
The risk score is a project-defined heuristic and should not be interpreted as a calibrated attack probability.

⚡ Real-Time Detection
Real-time packet monitoring is implemented using Scapy.

The system:

Captures live network packets
Groups packets into flows
Extracts behavioral features
Applies the trained scaler
Runs the Isolation Forest model
Calculates anomaly and risk scores
Stores detection results
Displays results on the dashboard
📊 SOC Dashboard
The Streamlit dashboard provides:

🟢 Live Detection Status
📡 Total Traffic
✅ Normal Traffic
🚨 Anomalies
🔴 High-Risk Events
📈 Anomaly Score Timeline
📊 Risk Distribution
🌐 Network Information
🚨 Critical Alerts
🔄 Automatic Dashboard Refresh
🛠️ Technology Stack
Technology	Purpose
Python	Core development
Scapy	Live packet capture
Pandas	Data processing
NumPy	Numerical operations
Scikit-learn	Machine Learning
Isolation Forest	Anomaly Detection
StandardScaler	Feature scaling
Joblib	Model storage
Streamlit	SOC Dashboard
Npcap	Windows packet capture
CIC-IDS2017	Dataset


📁 Project Structure
zero day ai/
│
├── data/
│   ├── raw/
│   └── processed/
│
├── models/
│   ├── scaler.pkl
│   └── isolation_forest.pkl
│
├── src/
│   ├── alerts.py
│   ├── capture.py
│   ├── detector.py
│   ├── features.py
│   ├── preprocessing.py
│   ├── risk.py
│   └── train.py
│
├── dashboard/
│   └── app.py
│
├── notebooks/
│
├── requirements.txt
├── README.md
└── .gitignore
🚀 Installation
Clone the repository:

git clone https://github.com/harsh993536/zero-day-attack-detection.git

Move into the project directory:

cd zero-day-attack-detection

Create a virtual environment:

python -m venv venv

Activate the environment on Windows:

.\venv\Scripts\activate

Install the required libraries:

pip install -r requirements.txt

▶️ Running the Project
Terminal 1 — Real-Time Detection
cd src
python capture.py

Terminal 2 — Dashboard
Open another terminal:

streamlit run dashboard/app.py

Open the dashboard:

http://localhost:8501
📚 Dataset
The project uses the CIC-IDS2017 dataset for network intrusion detection research and model development.

Dataset source:

https://www.unb.ca/cic/datasets/ids-2017.html

⚠️ Limitations
Anomaly detection cannot guarantee detection of every zero-day attack.
The risk score is a project-defined heuristic.
Real-time detection depends on packet-capture permissions and Npcap.
Network behavior can vary between environments.
Detected anomalies require further investigation.
🔮 Future Scope
Compare multiple anomaly detection algorithms
Add Autoencoder-based detection
Integrate threat intelligence
Add email/Telegram alerts
Improve risk-score calibration
Add attack-type classification
Add historical analytics
Deploy the dashboard to a cloud environment
👨‍💻 Author
Harsh Arjariya

B.Tech CSE Core
Chandigarh University