import pandas as pd
import joblib
import streamlit as st

from risk import calculate_risk_score, get_risk_level

# ---------------------------------------
# 1. Load trained model and scaler
# ---------------------------------------

model = joblib.load("models/isolation_forest.pkl")
scaler = joblib.load("models/scaler.pkl")

print("Model loaded successfully.")


# ---------------------------------------
# 2. Load cleaned network data
# ---------------------------------------

DATA_PATH = "data/processed/cleaned_network_data.csv"

df = pd.read_csv(DATA_PATH)

print("Dataset loaded.")
print("Dataset shape:", df.shape)


# ---------------------------------------
# 3. Select behavioral features
# ---------------------------------------

features = [
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

X = df[features]


# ---------------------------------------
# 4. Scale the data
# ---------------------------------------

X_scaled = scaler.transform(X)

print("Data scaled successfully.")


# ---------------------------------------
# 5. Predict anomalies
# ---------------------------------------

predictions = model.predict(X_scaled)

# Get Isolation Forest anomaly scores
anomaly_scores = model.decision_function(X_scaled)

df["Prediction"] = predictions
df["Anomaly Score"] = anomaly_scores


# ---------------------------------------
# 6. Convert prediction to status
# ---------------------------------------

df["Status"] = df["Prediction"].apply(
    lambda x: "ANOMALY" if x == -1 else "NORMAL"
)

df["Risk Score"] = df["Anomaly Score"].apply(
    calculate_risk_score
)

df["Risk Level"] = df["Risk Score"].apply(
    get_risk_level
)


# ---------------------------------------
# 7. Display results
# ---------------------------------------

print("\nDetection results:")
print(df["Status"].value_counts())


# ---------------------------------------
# 8. Display sample results
# ---------------------------------------

print("\nSample results:")

print(
    df[
        [
            "Label",
            "Prediction",
            "Status",
            "Anomaly Score",
            "Risk Score",
            "Risk Level"
        ]
    ].head(20)
)

# ---------------------------------------
# 9. Compare predictions with actual labels
# ---------------------------------------

print("\nActual labels vs AI detection:")

comparison = pd.crosstab(
    df["Label"],
    df["Status"]
)

print(comparison)


# ---------------------------------------
# 10. Model evaluation
# ---------------------------------------

from sklearn.metrics import (
    classification_report,
    confusion_matrix
)

# Convert actual labels to binary values
# BENIGN = 0
# Attack = 1

y_true = df["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

# Convert AI prediction
# NORMAL = 0
# ANOMALY = 1

y_pred = df["Prediction"].apply(
    lambda x: 0 if x == 1 else 1
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\nClassification Report:")
print(
    classification_report(
        y_true,
        y_pred,
        target_names=["NORMAL", "ATTACK"]
    )
)


# ---------------------------------------
# 11. Save detection results
# ---------------------------------------

output_path = "data/processed/detection_results.csv"

df.to_csv(output_path, index=False)

print("\nDetection results saved to:")
print(output_path)

# ---------------------------------------
# 12. Extract high-risk events
# ---------------------------------------

high_risk = df[df["Risk Level"] == "HIGH"].copy()

high_risk_path = "data/processed/high_risk_events.csv"

high_risk.to_csv(high_risk_path, index=False)

print("\nHigh-risk events:")
print(len(high_risk))

print("\nHigh-risk events saved to:")
print(high_risk_path)

# ---------------------------------------
# High-risk alerts
# ---------------------------------------

st.header("🚨 High-Risk Alerts")

high_risk_df = df[
    df["Risk Level"] == "HIGH"
].copy()

if len(high_risk_df) > 0:

    st.warning(
        f"{len(high_risk_df)} high-risk events detected!"
    )

    st.dataframe(
        high_risk_df[
            [
                "Label",
                "Status",
                "Anomaly Score",
                "Risk Score",
                "Risk Level"
            ]
        ].head(20),
        use_container_width=True
    )

else:

    st.success(
        "No high-risk events detected."
    )

# ---------------------------------------
# Risk distribution
# ---------------------------------------


    st.header("📊 Risk Distribution")

risk_summary = (
    df["Risk Level"]
    .value_counts()
    .reindex(
        ["LOW", "MEDIUM", "HIGH"],
        fill_value=0
    )
)

st.bar_chart(risk_summary)