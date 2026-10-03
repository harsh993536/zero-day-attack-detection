import pandas as pd
import os

# Dataset location
DATA_PATH = "data/raw"

# Get all CSV files
files = [
    file for file in os.listdir(DATA_PATH)
    if file.endswith(".csv")
]

print("CSV files found:", len(files))

# Read the first CSV
file_path = os.path.join(DATA_PATH, files[0])

print("\nLoading:")
print(file_path)

df = pd.read_csv(file_path)

# Remove spaces from column names
df.columns = df.columns.str.strip()

print("\nDataset shape:")
print(df.shape)

print("\nMissing values before cleaning:")
print(df.isnull().sum().sum())

print("\nInfinite values before cleaning:")
print((df.select_dtypes(include="number") == float("inf")).sum().sum())
print((df.select_dtypes(include="number") == float("-inf")).sum().sum())

# Replace infinite values with NaN
df = df.replace([float("inf"), float("-inf")], pd.NA)

# Remove rows containing missing values
df = df.dropna()

print("\nMissing values after cleaning:")
print(df.isnull().sum().sum())

print("\nDataset shape after cleaning:")
print(df.shape)

print("\nLabels after cleaning:")
print(df["Label"].value_counts())


# Behavioral features for AI model
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

print("\nSelected behavioral features:")

for feature in features:
    print(feature)

    # Keep only selected features and the label
selected_columns = [
    "Destination Port",
    "Protocol",
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
    "Average Packet Size",
    "Label"
]

df_clean = df[selected_columns].copy()

print("\nCleaned dataset shape:")
print(df_clean.shape)

print("\nCleaned dataset preview:")
print(df_clean.head())


# Save cleaned dataset
output_path = "data/processed/cleaned_network_data.csv"

df_clean.to_csv(output_path, index=False)

# Separate normal and attack traffic
normal_data = df_clean[df_clean["Label"] == "BENIGN"].copy()
attack_data = df_clean[df_clean["Label"] != "BENIGN"].copy()

print("\nNormal traffic:")
print(normal_data.shape)

print("\nAttack traffic:")
print(attack_data.shape)

print("\nCleaned dataset saved to:")
print(output_path)


normal_path = "data/processed/normal_traffic.csv"

normal_data.to_csv(normal_path, index=False)

print("\nNormal traffic saved to:")
print(normal_path)



from sklearn.preprocessing import StandardScaler
import joblib

# Features used by the AI model
X_normal = normal_data[features]

# Create scaler
scaler = StandardScaler()

# Fit scaler on normal traffic
X_scaled = scaler.fit_transform(X_normal)

print("\nScaled data shape:")
print(X_scaled.shape)

print("\nFirst 5 scaled rows:")
print(X_scaled[:5])


# Save the scaler for future predictions
scaler_path = "models/scaler.pkl"

joblib.dump(scaler, scaler_path)

print("\nScaler saved to:")
print(scaler_path)