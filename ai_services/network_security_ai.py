import torch
import torch.nn as nn
import numpy as np
import joblib
import paho.mqtt.client as mqtt
import json
import time
import sys

# ================= CLASS DEFS (Must match training) =================
class RobustEnsemble(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super(RobustEnsemble, self).__init__()
        self.bilstm = nn.LSTM(input_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.rnn = nn.RNN(input_dim, hidden_dim, batch_first=True, bidirectional=False)
        self.fc1 = nn.Linear(hidden_dim * 3, 32)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.5)
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        lstm_out, _ = self.bilstm(x)
        rnn_out, _ = self.rnn(x)
        combined = torch.cat((lstm_out[:, -1, :], rnn_out[:, -1, :]), dim=1)
        return self.relu(self.fc1(combined))

class KELM:
    def __init__(self, C=1, gamma=0.1):
        self.C, self.gamma = C, gamma
        self.beta, self.X_train = None, None
    
    def _rbf(self, X, Y):
        X_norm = np.sum(X ** 2, axis=-1).reshape(-1, 1)
        Y_norm = np.sum(Y ** 2, axis=-1).reshape(1, -1)
        return np.exp(-self.gamma * (X_norm + Y_norm - 2 * np.dot(X, Y.T)))

    def predict_proba(self, X):
        out = np.dot(self._rbf(X, self.X_train), self.beta)
        exp = np.exp(out - np.max(out, axis=1, keepdims=True))
        return exp / np.sum(exp, axis=1, keepdims=True)

# ================= LOAD ASSETS =================
print("⏳ Loading Network Security AI...")
try:
    # Based on your logs, the model expects 104 features
    INPUT_DIM = 104 
    dev = torch.device("cpu")
    
    ext = RobustEnsemble(INPUT_DIM, 32, 5).to(dev)
    ext.load_state_dict(torch.load("models/ecu_ensemble_model.pth", map_location=dev))
    ext.eval()
    
    kelm = joblib.load("models/kelm_final.pkl")
    scaler = joblib.load("models/feature_scaler.pkl")
    print("✅ Network AI Loaded (BiLSTM + KELM)")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    sys.exit(1)

# ================= MQTT LOGIC =================
BROKER = "127.0.0.1"
TOPIC_INPUT = "ioht/network/data"
TOPIC_OUTPUT_FUSION = "fusion/network_alert" # To Fusion Service
TOPIC_OUTPUT_DASH = "ioht/network/result"    # To Dashboard

def on_connect(client, userdata, flags, rc, properties=None):
    print("🛡️ Security AI Online.")
    client.subscribe(TOPIC_INPUT)

def on_message(client, userdata, msg):
    try:
        pl = json.loads(msg.payload.decode())
        raw = np.array(pl['features'])
        
        # --- CRITICAL FIX IS HERE ---
        # Reshape to (Batch=1, Time=1, Features=104)
        # This makes it a 3D Tensor, which the LSTM expects.
        t = torch.tensor(raw, dtype=torch.float32).view(1, 1, -1).to(dev)
        
        # 1. Feature Extraction (BiLSTM)
        with torch.no_grad(): 
            feat = ext(t).cpu().numpy()
        
        # 2. Classification (KELM)
        feat_scaled = scaler.transform(feat)
        probs = kelm.predict_proba(feat_scaled)[0]
        idx = np.argmax(probs)
        
        classes = ["Normal", "DoS", "ARP Spoofing", "Smurf", "Port Scan"]
        pred = classes[idx]
        conf = float(probs[idx])
        
        # Debug Output
        true_lbl = pl.get("true_label", "?")
        # Map integer true labels to text for cleaner logs
        lbl_map = {0: "Normal", 1: "DoS", 2: "ARP", 3: "Smurf", 4: "Scan"}
        truth_str = lbl_map.get(true_lbl, str(true_lbl))
        
        icon = "🟢" if pred == "Normal" else "🔴"
        print(f"{icon} Det: {pred} ({conf:.1%}) | True: {truth_str}")
        
        # 3. Publish to Fusion Service (Matches FusionState keys)
        alert = {
            "timestamp": time.time(),
            "predicted_class": pred,  # Fusion looks for 'predicted_class' or 'attack_class'
            "confidence": conf,
            "src": pl.get("device", "unknown_ip"),
            "features": raw.tolist(),
            "true_label": true_lbl
        }
        client.publish(TOPIC_OUTPUT_FUSION, json.dumps(alert))
        
        # 4. Publish to Dashboard (For Visuals)
        client.publish(TOPIC_OUTPUT_DASH, json.dumps({
            "diagnosis": pred,
            "confidence": conf,
            "timestamp": pl['timestamp']
        }))

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start MQTT
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Net_AI")
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 1883)
client.loop_forever()