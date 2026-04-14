

import os
import time
import joblib
import pandas as pd
import subprocess
import datetime
import json

# --- CONFIGURATION ---
# Replace with your actual model filenames if different
MODEL_FILE = 'general_model.pkl'
SCALER_FILE = 'general_scaler.pkl'

# Replace with your actual IP to prevent locking yourself out
ADMIN_IP = "119.160.199.91" 

GOLDEN_FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 'Flow Bytes/s']
stats = {} 

# --- LOAD MODELS ---
try:
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    print("✅ AI Brain Loaded Successfully.")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit()

def log_dual_format(ip, features, prediction, proba):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. HUMAN READABLE (For your Professor)
    attack_type = "Brute Force / Behavioral Anomaly"
    with open("human_report.log", "a") as f:
        f.write(f"\n[{timestamp}] ALERT: {attack_type} detected from IP: {ip}\n")
        f.write(f"REASON: AI identified high-frequency connection patterns.\n")
        f.write(f"ACTION: Firewall updated to BLOCK this source.\n")
        f.write("-" * 50 + "\n")

    # 2. ENGINEER READABLE (Technical JSON)
    engineer_data = {
        "timestamp": timestamp,
        "source_ip": ip,
        "features": features,
        "prediction_index": int(prediction),
        "ai_confidence": round(float(max(proba)), 4),
        "firewall_action": "INPUT_DROP"
    }
    with open("engineer_metrics.json", "a") as f:
        f.write(json.dumps(engineer_data) + "\n")
    print(f"📄 Logs generated: human_report.log and engineer_metrics.json")

def run_ai_logic(ip, duration):
    # Mapping real-time behavior to the 5 Golden Features
    features = {
        'Flow Duration': duration,
        'Total Fwd Packets': 5,  # Estimated flow based on SSH handshake
        'Total Backward Packets': 4,
        'Flow Packets/s': 9 / (duration if duration > 0 else 0.1),
        'Flow Bytes/s': 1500 / (duration if duration > 0 else 0.1)
    }
    
    # Prepare data for model
    df = pd.DataFrame([features])[GOLDEN_FEATURES]
    X_scaled = scaler.transform(df)
    
    prediction = model.predict(X_scaled)[0]
    proba = model.predict_proba(X_scaled)[0]

    if prediction == 1:
        print(f"🚨 [BLOCK] AI detected an attack pattern from {ip}!")
        os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")
        log_dual_format(ip, features, prediction, proba)
    else:
        print(f"✔️ [SAFE] Traffic from {ip} analyzed and cleared.")

def monitor_traffic():
    print(f"🛡️ GUARDIAN ACTIVE. Monitoring for SSH anomalies...")
    print(f"Whitelisted Admin: {ADMIN_IP}")

    # Use journalctl to ensure we catch logs even if rsyslog is slow
    cmd = "journalctl -u ssh -f -o cat"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    
    for line in iter(process.stdout.readline, b''):
        line = line.decode('utf-8').strip()
        
        # Trigger on 'Failed password' or 'Connection closed' (standard attack markers)
        if "Failed password" in line or "Connection closed" in line:
            parts = line.split()
            try:
                # Find the IP address in the text
                ip = next(p for p in parts if p.count('.') == 3)
                if ip == ADMIN_IP: continue
                
                now = time.time()
                if ip not in stats:
                    stats[ip] = {'start': now, 'attempts': 1}
                    print(f"[*] New connection tracked: {ip}")
                else:
                    duration = now - stats[ip]['start']
                    stats[ip]['attempts'] += 1
                    print(f"[*] Attempt {stats[ip]['attempts']} from {ip}...")
                    
                    # After 3 attempts, run the AI check
                    if stats[ip]['attempts'] >= 3:
                        run_ai_logic(ip, duration)
                        stats[ip] = {'start': now, 'attempts': 0} # Reset counter
            except Exception:
                continue

if __name__ == "__main__":
    # Clear rules first to ensure we aren't blocking our own test
    os.system("sudo iptables -F")
    try:
        monitor_traffic()
    except KeyboardInterrupt:
        print("\nShutting down Guardian safely.")
