import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest

# ---------------------------------------
# 1. Load normal traffic
# ---------------------------------------

DATA_PATH = "data/processed/normal_traffic.csv"

df = pd.read_csv(DATA_PATH)

print("Normal traffic loaded.")
print("Dataset shape:", df.shape)


# ---------------------------------------
# 2. Select behavioral features
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

print("\nFeatures selected:", len(features))
print("Feature data shape:", X.shape)


# ---------------------------------------
# 3. Load previously trained scaler
# ---------------------------------------

scaler = joblib.load("models/scaler.pkl")

X_scaled = scaler.transform(X)

print("\nData scaled successfully.")
print("Scaled data shape:", X_scaled.shape)


# ---------------------------------------
# 4. Create Isolation Forest
# ---------------------------------------

model = IsolationForest(
    n_estimators=200,
    contamination=0.01,
    random_state=42
)


# ---------------------------------------
# 5. Train the model
# ---------------------------------------

print("\nTraining Isolation Forest...")

model.fit(X_scaled)

print("Training completed!")


# ---------------------------------------
# 6. Save the model
# ---------------------------------------

model_path = "models/isolation_forest.pkl"

joblib.dump(model, model_path)

print("\nModel saved to:")
print(model_path)