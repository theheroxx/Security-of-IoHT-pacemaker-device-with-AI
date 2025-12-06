# level4_pipeline.py
# ====================================================
# LEVEL 4 - Export, Evaluate, Inference service, Simulator
# ====================================================
import os
import json
import time
import joblib
import numpy as np
import torch
import torch.nn.functional as F
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_auc_score)
import matplotlib.pyplot as plt
import seaborn as sns
import paho.mqtt.client as mqtt

# -----------------------------
# Config - adjust paths here
# -----------------------------
ARTIFACT_DIR = "./"
# Use the "Scientific" paths we created earlier
MODEL_PATH   = os.path.join(ARTIFACT_DIR, "ecu_ensemble_model.pth")
SCALER_PATH  = os.path.join(ARTIFACT_DIR, "minmax_scaler.pkl")
ENC_PATH     = os.path.join(ARTIFACT_DIR, "label_encoders.pkl")
NPZ_PATH     = os.path.join(ARTIFACT_DIR, "ECU_ready_scientific_no_smote.npz")
CLASS_MAP_FN = os.path.join(ARTIFACT_DIR, "class_mapping.json")

PUBLISH_TOPIC = "ioht/network/data"       # Input to AI
PRED_TOPIC    = "ioht/network/prediction" # Output from AI
MQTT_BROKER   = "127.0.0.1"
MQTT_PORT     = 1883

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Device:", DEVICE)

# -----------------------------
# Model definition (Matches Level 3 RobustEnsemble)
# -----------------------------
class RobustEnsemble(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super(RobustEnsemble, self).__init__()
        self.bilstm = nn.LSTM(input_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.rnn = nn.RNN(input_dim, hidden_dim, batch_first=True, bidirectional=False)
        self.fc1 = nn.Linear(hidden_dim * 3, 32) # Matches the Saved Model
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.5)
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        lstm_out, _ = self.bilstm(x)
        rnn_out, _ = self.rnn(x)
        # Concatenate: BiLSTM Last Step + RNN Last Step
        combined = torch.cat((lstm_out[:, -1, :], rnn_out[:, -1, :]), dim=1)
        x = self.fc1(combined)
        x = self.relu(x)
        x = self.dropout(x)
        return self.fc2(x)

# -----------------------------
# Utilities
# -----------------------------
def load_artifacts():
    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    encoders = joblib.load(ENC_PATH) if os.path.exists(ENC_PATH) else None
    return scaler, encoders

def save_class_mapping():
    # 0: Normal, 1: DoS, 2: ARP, 3: Smurf, 4: Scan
    mapping = {0: "Normal", 1: "DoS", 2: "ARP Spoofing", 3: "Smurf Attack", 4: "Port Scan"}
    with open(CLASS_MAP_FN, "w") as f:
        json.dump(mapping, f, indent=2)
    print("Saved class mapping:", CLASS_MAP_FN)
    return mapping

# -----------------------------
# 1) Export artifacts
# -----------------------------
def export_artifacts():
    save_class_mapping()
    print("Checking Artifacts at:", ARTIFACT_DIR)
    for p in [MODEL_PATH, SCALER_PATH, ENC_PATH, NPZ_PATH]:
        print(" -", p, "->", "✅ FOUND" if os.path.exists(p) else "❌ MISSING")

# -----------------------------
# 2) Load model
# -----------------------------
def build_and_load_model(npz_path=NPZ_PATH, model_path=MODEL_PATH):
    data = np.load(npz_path)
    input_dim = data['X_train'].shape[2]
    # We trained with 5 classes
    num_classes = 5
    hidden_dim = 32 # Matches Level 3 config

    model = RobustEnsemble(input_dim, hidden_dim, num_classes).to(DEVICE)

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    state = torch.load(model_path, map_location=DEVICE)
    model.load_state_dict(state)
    model.eval()
    print("🧠 Model Loaded Successfully")
    return model

# -----------------------------
# 3) Evaluate on test set
# -----------------------------
def evaluate_model(model, npz_path=NPZ_PATH, save_dir=ARTIFACT_DIR):
    print("📊 Starting Evaluation...")
    data = np.load(npz_path)
    X_test = data['X_test']
    y_test = data['y_test']

    bs = 256
    preds = []
    probs = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X_test), bs):
            xb = torch.tensor(X_test[i:i+bs], dtype=torch.float32).to(DEVICE)
            logits = model(xb)
            p = F.softmax(logits, dim=1).cpu().numpy()
            preds.append(p.argmax(axis=1))
            probs.append(p)
    y_pred = np.concatenate(preds)

    # Metrics
    print("\nClassification Report:")
    target_names = ["Normal", "DoS", "ARP", "Smurf", "Scan"]
    print(y_test, y_pred, target_names=target_names)

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.show()

# -----------------------------
# 4) Inference Service (The AI Brain)
# -----------------------------
class InferenceService:
    def __init__(self, model, scaler=None, encoders=None, seq_len=10):
        self.model = model
        self.scaler = scaler
        self.encoders = encoders
        self.seq_len = seq_len
        self.buffer = []

        # Paho v2.0 Fix
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.connect(MQTT_BROKER, MQTT_PORT)
        print("🛡️ Security AI connected to MQTT")

    def on_connect(self, client, userdata, flags, rc, properties):
        print("✅ Connected to Broker")
        client.subscribe(PUBLISH_TOPIC)

    def process_raw_packet(self, raw_packet):
        x = np.asarray(raw_packet, dtype=float).reshape(1, -1)

        # NOTE: Since we are simulating with data from the .npz file (which is ALREADY scaled),
        # we do NOT apply the scaler here.
        # If connecting to real live network traffic (Wireshark), uncomment the line below:
        # if self.scaler: x = self.scaler.transform(x)

        self.buffer.append(x.flatten())
        if len(self.buffer) > self.seq_len:
            self.buffer.pop(0)

        if len(self.buffer) == self.seq_len:
            # Form sequence (1, 10, Features)
            seq = np.stack(self.buffer, axis=0).reshape(1, self.seq_len, -1)
            xb = torch.tensor(seq, dtype=torch.float32).to(DEVICE)

            with torch.no_grad():
                logits = self.model(xb)
                probs = F.softmax(logits, dim=1).cpu().numpy().tolist()[0]
                pred_idx = int(np.argmax(probs))

            # Map index to Name
            mapping = {0: "Normal", 1: "DoS", 2: "ARP", 3: "Smurf", 4: "Scan"}
            pred_name = mapping.get(pred_idx, "Unknown")

            payload = {
                "prediction_idx": pred_idx,
                "diagnosis": pred_name,
                "confidence": max(probs),
                "timestamp": time.time()
            }
            self.client.publish(PRED_TOPIC, json.dumps(payload))
            print(f"👉 Detected: {pred_name} ({max(probs):.2f})")

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            if "features" in payload:
                self.process_raw_packet(payload["features"])
        except Exception as e:
            print(f"Error: {e}")

    def start(self):
        print("👀 Security AI Listening...")
        self.client.loop_forever()

# -----------------------------
# 5) Simulator (Sends Test Data)
# -----------------------------
def simulator_publish(npz_path=NPZ_PATH, topic=PUBLISH_TOPIC, delay=0.1):
    data = np.load(npz_path)
    X_test = data['X_test']

    # Paho v2.0 Fix
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(MQTT_BROKER, MQTT_PORT)
    client.loop_start()

    print(f"📡 Simulating Network Traffic to {topic}...")
    try:
        # Loop through test samples
        # Each sample is already a sequence of 10. We send the last packet of each.
        for seq in X_test:
            # Send the last packet of the window
            # (In real life, packets arrive one by one)
            features = seq[-1].tolist()

            payload = {"features": features}
            client.publish(topic, json.dumps(payload))
            time.sleep(delay)

    except KeyboardInterrupt:
        print("Simulation Stopped")
    finally:
        client.loop_stop()
        client.disconnect()

# -----------------------------
# MAIN CLI
# -----------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", type=str, default="all",
                        choices=["all", "eval", "serve", "sim"],
                        help="Choose: 'eval' (Test Model), 'serve' (Run AI), 'sim' (Send Data)")
    args = parser.parse_args()

    if args.action == "all":
        export_artifacts()
        model = build_and_load_model()
        evaluate_model(model)

    elif args.action == "eval":
        model = build_and_load_model()
        evaluate_model(model)

    elif args.action == "serve":
        scaler, enc = load_artifacts()
        model = build_and_load_model()
        svc = InferenceService(model, scaler=scaler, encoders=enc)
        svc.start()

    elif args.action == "sim":
        simulator_publish(delay=0.1)