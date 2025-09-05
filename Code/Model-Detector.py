import numpy as np
import pandas as pd
import joblib
import os
import sys
from datetime import datetime

def main():
    if len(sys.argv) < 2:
        print("Usage: python Model-Detector.py <input_csv_file>")
        sys.exit(1)

    input_csv = sys.argv[1]

    # === Load CSV ===
    try:
        raw_data = pd.read_csv(input_csv)
        print(f"Data loaded: {raw_data.shape[0]} rows, {raw_data.shape[1]} columns")
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    data = raw_data.copy()

    # === Drop unnecessary columns ===
    cols_to_drop = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol', 'Timestamp', 'Label']
    data.drop(columns=[col for col in cols_to_drop if col in data.columns], inplace=True)

    # === Rename columns ===
    rename_map = {
        'Dst Port': 'Destination Port',
        'Tot Fwd Pkts': 'Total Fwd Packets',
        'Tot Bwd Pkts': 'Total Backward Packets',
        'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
        'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
        'Fwd Pkt Len Max': 'Fwd Packet Length Max',
        'Fwd Pkt Len Min': 'Fwd Packet Length Min',
        'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
        'Fwd Pkt Len Std': 'Fwd Packet Length Std',
        'Bwd Pkt Len Max': 'Bwd Packet Length Max',
        'Bwd Pkt Len Min': 'Bwd Packet Length Min',
        'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
        'Bwd Pkt Len Std': 'Bwd Packet Length Std',
        'Flow Byts/s': 'Flow Bytes/s',
        'Flow Pkts/s': 'Flow Packets/s',
        'Fwd IAT Tot': 'Fwd IAT Total',
        'Bwd IAT Tot': 'Bwd IAT Total',
        'Fwd Header Len': 'Fwd Header Length',
        'Bwd Header Len': 'Bwd Header Length',
        'Fwd Pkts/s': 'Fwd Packets/s',
        'Bwd Pkts/s': 'Bwd Packets/s',
        'Pkt Len Min': 'Min Packet Length',
        'Pkt Len Max': 'Max Packet Length',
        'Pkt Len Mean': 'Packet Length Mean',
        'Pkt Len Std': 'Packet Length Std',
        'Pkt Len Var': 'Packet Length Variance',
        'FIN Flag Cnt': 'FIN Flag Count',
        'SYN Flag Cnt': 'SYN Flag Count',
        'RST Flag Cnt': 'RST Flag Count',
        'PSH Flag Cnt': 'PSH Flag Count',
        'ACK Flag Cnt': 'ACK Flag Count',
        'URG Flag Cnt': 'URG Flag Count',
        'ECE Flag Cnt': 'ECE Flag Count',
        'CWE Flag Count': 'CWE Flag Count',
        'Pkt Size Avg': 'Average Packet Size',
        'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
        'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
        'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
        'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
        'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
        'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
        'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
        'Subflow Fwd Pkts': 'Subflow Fwd Packets',
        'Subflow Fwd Byts': 'Subflow Fwd Bytes',
        'Subflow Bwd Pkts': 'Subflow Bwd Packets',
        'Subflow Bwd Byts': 'Subflow Bwd Bytes',
        'Init Fwd Win Byts': 'Init_Win_bytes_forward',
        'Init Bwd Win Byts': 'Init_Win_bytes_backward',
        'Fwd Act Data Pkts': 'act_data_pkt_fwd',
        'Fwd Seg Size Min': 'min_seg_size_forward'
    }
    data.rename(columns={k: v for k, v in rename_map.items() if k in data.columns}, inplace=True)

    # === Drop low-quality modeling columns if they exist ===
    drop_columns = [
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate'
    ]
    data.drop(columns=[col for col in drop_columns if col in data.columns], inplace=True)

    # === Handle inf and NaN ===
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in ['Flow Bytes/s', 'Flow Packets/s']:
        if col in data.columns:
            data[col] = data[col].fillna(data[col].median())
    data.dropna(inplace=True)

    # === Load scaler, PCA, and model with joblib ===
    print("Loading scaler, PCA, and model with joblib...")
    try:
        scaler = joblib.load("Model/scaler.joblib")
        pca = joblib.load("Model/pca.joblib")
        model = joblib.load("Model/current_model.joblib")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        sys.exit(1)

    # === Standardize and transform features ===
    scaled_features = scaler.transform(data)
    reduced_features = pca.transform(scaled_features)

    # === Predict ===
    print("Predicting...")
    predictions_encoded = model.predict(reduced_features)

    # === Map numeric predictions to labels ===
    label_map = {
        0: "BENIGN",
        1: "DDoS",
        2: "DoS",
        3: "Port Scan",
        4: "Web Attack"
    }
    predictions = [label_map.get(pred, "Unknown") for pred in predictions_encoded]

    # === Merge predictions ===
    raw_data = raw_data.loc[data.index].copy()
    raw_data["Prediction"] = predictions


        # ************************************
    # === Print Summary Statistics ===
    # ************************************
    total_flows = len(data)
    benign_count = predictions.count("BENIGN")
    malicious_count = total_flows - benign_count

    print("\n[+] Prediction summary:")
    print("*************************************************************")
    print("TRAFFIC SUMMARY")
    print("-------------------------------------------------------------")
    print(f"Data loaded              : {total_flows} rows, {data.shape[1]} columns")
    print(f"BENIGN flows             : {benign_count} ({benign_count / total_flows:.2%})")
    print(f"MALICIOUS flows          : {malicious_count} ({malicious_count / total_flows:.2%})")
    print("*************************************************************")
    
    # Detailed class breakdown
    print("MALICIOUS TRAFFIC BREAKDOWN")
    print("-------------------------------------------------------------")
    class_counts = pd.Series(predictions).value_counts()
    for cls, count in class_counts.items():
        percent = (count / total_flows) * 100
        print(f"{cls:<25}: {count} ({percent:.2f}%)")
    print("*************************************************************")

    # Maliciousness rating
    malicious_ratio = malicious_count / total_flows
    if malicious_ratio >= 0.9:
        rating = "10/10 - Extremely Malicious"
    elif malicious_ratio >= 0.7:
        rating = "8/10 - Highly Malicious"
    elif malicious_ratio >= 0.4:
        rating = "6/10 - Moderately Malicious"
    elif malicious_ratio >= 0.1:
        rating = "4/10 - Mostly Benign"
    else:
        rating = "2/10 - Clean or Minimal Threat"

    print("TRAFFIC MALICIOUSNESS RATING")
    print("-------------------------------------------------------------")
    print(f"Estimated Threat Level   : {rating}")
    print("*************************************************************\n")
    

    # === Save outputs ===
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Malicious
    malicious = raw_data[raw_data["Prediction"] != "BENIGN"]
    if not malicious.empty:
        os.makedirs("CSVs/malicious", exist_ok=True)
        malicious_output_path = f"CSVs/malicious/predictions_{timestamp}.csv"
        malicious.to_csv(malicious_output_path, index=False)
        print(f"\n[OK] Saved {len(malicious)} malicious flows to: {malicious_output_path}")
    else:
        print("\nNo malicious flows detected.")

    # Benign
    benign = raw_data[raw_data["Prediction"] == "BENIGN"]
    if not benign.empty:
        os.makedirs("CSVs/Benign", exist_ok=True)
        benign_output_path = f"CSVs/Benign/predictions_{timestamp}.csv"
        benign.to_csv(benign_output_path, index=False)
        print(f"\n[OK] Saved {len(benign)} benign flows to: {benign_output_path}")
    else:
        print("No benign flows detected.")

if __name__ == "__main__":
    main()
