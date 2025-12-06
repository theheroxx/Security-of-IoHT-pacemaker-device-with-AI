import torch
import torch.nn as nn
import numpy as np
import joblib
import paho.mqtt.client as mqtt
import json
import os

# ==========================================
# 1. CLASS DEFINITIONS (Must match saved models)
# ==========================================
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
        features = self.fc1(combined)
        features = self.relu(features)
        return features

class KELM:
    def __init__(self, C=1, gamma=0.1):
        self.C = C
        self.gamma = gamma
        self.beta = None
        self.X_train = None

    def _rbf_kernel(self, X, Y):
        X_norm = np.sum(X ** 2, axis=-1).reshape(-1, 1)
        Y_norm = np.sum(Y ** 2, axis=-1).reshape(1, -1)
        dist = X_norm + Y_norm - 2 * np.dot(X, Y.T)
        return np.exp(-self.gamma * dist)

    def predict(self, X):
        Omega_test = self._rbf_kernel(X, self.X_train)
        outputs = np.dot(Omega_test, self.beta)
        return np.argmax(outputs, axis=1)

    # NEW: Calculate Probability/Confidence
    def predict_proba(self, X):
        Omega_test = self._rbf_kernel(X, self.X_train)
        outputs = np.dot(Omega_test, self.beta)
        # Apply Softmax to get probabilities (0.0 to 1.0)
        exp_scores = np.exp(outputs - np.max(outputs, axis=1, keepdims=True))
        probs = exp_scores / np.sum(exp_scores, axis=1, keepdims=True)
        return probs

# ==========================================
# 2. LOAD MODELS
# ==========================================
BASE_DIR = "models"
MODEL_PTH = f"{BASE_DIR}/ecu_ensemble_model.pth"
KELM_PKL = f"{BASE_DIR}/kelm_final.pkl"
SCALER_PKL = f"{BASE_DIR}/feature_scaler.pkl"

device = torch.device("cpu")

print("⏳ Loading Hybrid AI System...")
try:
    # 1. Load Feature Extractor
    # Note: Use 104 if your previous error log said 104, otherwise 107.
    # Based on your last error, it was 104.
    INPUT_DIM = 104 
    extractor = RobustEnsemble(INPUT_DIM, 32, 5).to(device)
    extractor.load_state_dict(torch.load(MODEL_PTH, map_location=device))
    extractor.eval()
    
    # 2. Load Classifier
    kelm_classifier = joblib.load(KELM_PKL)
    
    # 3. Load Scaler
    feature_scaler = joblib.load(SCALER_PKL)
    
    print("✅ Hybrid Model Loaded.")
except Exception as e:
    print(f"❌ Load Error: {e}")
    exit()

# ==========================================
# 3. INFERENCE LOGIC
# ==========================================
CLASS_NAMES = ["Normal", "DoS Attack", "ARP Spoofing", "Smurf Attack", "Port Scan"]

def process_traffic(sequence):
    # 1. Tensor
    seq_tensor = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0).to(device)
    
    # 2. Extract Features
    with torch.no_grad():
        deep_features = extractor(seq_tensor).cpu().numpy()
        
    # 3. Scale
    scaled_features = feature_scaler.transform(deep_features)
    
    # 4. Classify with Confidence
    probs = kelm_classifier.predict_proba(scaled_features)[0]
    pred_idx = np.argmax(probs)
    confidence = probs[pred_idx]
    
    return int(pred_idx), float(confidence)

# ==========================================
# 4. MQTT
# ==========================================
BROKER = "127.0.0.1"
TOPIC_INPUT = "ioht/network/data"
TOPIC_RESULT = "ioht/network/result"

def on_connect(client, userdata, flags, rc, properties):
    print("🛡️ Security AI Online.")
    client.subscribe(TOPIC_INPUT)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        features = payload['features']
        
        # Inference
        result_idx, conf = process_traffic(features)
        result_name = CLASS_NAMES[result_idx]
        
        # Console Log
        true_label = payload.get('true_label', '?')
        icon = "🟢" if result_idx == 0 else "🔴"
        print(f"{icon} {result_name} ({conf:.1%}) [True: {true_label}]")
        
        # Publish Result (WITH CONFIDENCE KEY)
        result_payload = {
            "timestamp": payload['timestamp'],
            "diagnosis": result_name,
            "is_attack": (result_idx != 0),
            "confidence": conf  # <--- FIXED: Added this key
        }
        client.publish(TOPIC_RESULT, json.dumps(result_payload))
        
    except Exception as e:
        print(f"Error: {e}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Security_AI")
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.loop_forever()