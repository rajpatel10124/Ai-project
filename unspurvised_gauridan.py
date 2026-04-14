import os
import time
import joblib
import pandas as pd
import subprocess
import datetime
import json
import numpy as np

# --- CONFIGURATION ---
MODEL_FILE = 'unsupervised_mixed_model.pkl'
SCALER_FILE = 'unsupervised_mixed_scaler.pkl'
ADMIN_IP = "119.160.199.91" 
GOLDEN_FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 'Flow Bytes/s']
stats = {} 

# --- LOAD UNSUPERVISED MODELS ---
try:
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    print("✅ Unsupervised Mixed Model Loaded.")
except Exception as e:
    print(f"❌ Error loading: {e}")
    exit()

def log_incident(ip, features, score):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. HUMAN LOG
    with open("human_report.log", "a") as f:
        f.write(f"\n[{timestamp}] UNKNOWN ANOMALY: IP {ip} deviated from baseline.\n")
        f.write(f"REASON: Unsupervised AI flagged this behavior as an outlier.\n")
        f.write(f"ACTION: IP blocked to maintain system stability.\n")
        f.write("-" * 50 + "\n")

    # 2. ENGINEER LOG
    engineer_data = {
        "timestamp": timestamp,
        "source_ip": ip,
        "features": features,
        "anomaly_score": float(score), # Lower score = More anomalous
        "model_type": "IsolationForest_Mixed_Dataset"
    }
    with open("engineer_metrics.json", "a") as f:
        f.write(json.dumps(engineer_data) + "\n")

def run_unsupervised_logic(ip, duration):
    # Mapping live behavior to our Golden Features
    features = {
        'Flow Duration': duration,
        'Total Fwd Packets': 6, 
        'Total Backward Packets': 5,
        'Flow Packets/s': 11 / (duration if duration > 0 else 0.1),
        'Flow Bytes/s': 1800 / (duration if duration > 0 else 0.1)
    }
    
    df = pd.DataFrame([features])[GOLDEN_FEATURES]
    X_scaled = scaler.transform(df)
    
    # Isolation Forest returns: 1 for normal, -1 for anomaly
    prediction = model.predict(X_scaled)[0]
    # Decision_function returns the anomaly score (negative values are anomalies)
    score = model.decision_function(X_scaled)[0]

    if prediction == -1:
        print(f"🚨 [ANOMALY DETECTED] IP {ip} is an outlier (Score: {score:.4f})")
        os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")
        log_incident(ip, features, score)
    else:
        print(f"✔️ [NORMAL] IP {ip} fits the learned baseline.")

def monitor_traffic():
    print(f"🛡️ UNSUPERVISED GUARDIAN ACTIVE. Baseline: CIC + UNSW Mixed.")
    process = subprocess.Popen("journalctl -u ssh -f -o cat", shell=True, stdout=subprocess.PIPE)
    
    for line in iter(process.stdout.readline, b''):
        line = line.decode('utf-8').strip()
        if "Failed password" in line or "Connection closed" in line:
            parts = line.split()
            try:
                ip = next(p for p in parts if p.count('.') == 3)
                if ip == ADMIN_IP: continue
                
                now = time.time()
                if ip not in stats:
                    stats[ip] = {'start': now, 'attempts': 1}
                else:
                    duration = now - stats[ip]['start']
                    stats[ip]['attempts'] += 1
                    print(f"[*] Analyzing Attempt {stats[ip]['attempts']} from {ip}...")
                    
                    if stats[ip]['attempts'] >= 3:
                        run_unsupervised_logic(ip, duration)
                        stats[ip] = {'start': now, 'attempts': 0}
            except:
                continue

if __name__ == "__main__":
    os.system("sudo iptables -F")
    monitor_traffic()