import pandas as pd
import numpy as np
import os, joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# PATHS
CIC_PATH = '/home/snr/D-Drive/sem-6/ai/project/MachineLearningCSV/MachineLearningCVE'
UNSW_PATH = '/home/snr/D-Drive/sem-6/ai/project/unsb-nb15/UNSW_NB15_testing-set.csv'

# CORRECT CASE for CIC-IDS (F is capital)
GOLDEN_FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 'Flow Bytes/s']

def train_dual_unsupervised():
    print("🚀 Step 1: Merging Datasets for Global Clustering...")
    master_chunks = []

    # --- PART A: Extracting from CIC-IDS ---
    all_cic_files = [f for f in os.listdir(CIC_PATH) if f.endswith('.csv')]
    for file in all_cic_files:
        df = pd.read_csv(os.path.join(CIC_PATH, file))
        # Clean column names (removes spaces and fixes casing issues)
        df.columns = df.columns.str.strip().str.replace('fwd', 'Fwd').str.replace('backward', 'Backward')
        
        try:
            df_subset = df[GOLDEN_FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
            master_chunks.append(df_subset.sample(frac=0.02))
        except KeyError as e:
            print(f"⚠️ Skipping {file} due to missing columns: {e}")

    # --- PART B: Extracting from UNSW-NB15 ---
    # Map UNSW's weird names to our exact GOLDEN_FEATURES
    mapping = {
        'dur': 'Flow Duration', 
        'spkts': 'Total Fwd Packets', 
        'dpkts': 'Total Backward Packets', 
        'sload': 'Flow Packets/s', 
        'dload': 'Flow Bytes/s'
    }
    
    if os.path.exists(UNSW_PATH):
        df_unsw = pd.read_csv(UNSW_PATH).rename(columns=mapping)
        # Only keep the columns we need
        df_unsw = df_unsw[GOLDEN_FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
        master_chunks.append(df_unsw.sample(frac=0.1))
    else:
        print("❌ UNSW Dataset file not found at path.")

    # Combine everything
    if not master_chunks:
        print("❌ No data collected. Check your file paths!")
        return

    final_df = pd.concat(master_chunks)
    print(f"📊 Training on {len(final_df)} mixed network flows...")
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(final_df)

    # Isolation Forest
    model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
    model.fit(X_scaled)

    joblib.dump(model, 'unsupervised_mixed_model.pkl')
    joblib.dump(scaler, 'unsupervised_mixed_scaler.pkl')
    print("✅ Dual-Dataset Unsupervised Model Saved successfully.")

if __name__ == "__main__":
    train_dual_unsupervised()