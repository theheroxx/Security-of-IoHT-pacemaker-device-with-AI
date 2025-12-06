import torch
import torch.nn as nn
import numpy as np
import paho.mqtt.client as mqtt
import json
import sys

# ==========================================
# 1. MODEL ARCHITECTURE
# ==========================================
class BiLSTM_Autoencoder(nn.Module):
    def __init__(self, seq_len=140, n_features=1):
        super(BiLSTM_Autoencoder, self).__init__()
        self.conv1 = nn.Conv1d(1, 32, 7, padding=3)
        self.relu = nn.ReLU()
        self.pool = nn.MaxPool1d(2)
        self.lstm_enc = nn.LSTM(32, 64, batch_first=True, bidirectional=True)
        self.lstm_dec = nn.LSTM(128, 64, batch_first=True, bidirectional=True)
        self.upsample = nn.Upsample(scale_factor=2)
        self.conv2 = nn.Conv1d(128, 1, 7, padding=3)

    def forward(self, x):
        x = x.permute(0, 2, 1)
        x = self.pool(self.relu(self.conv1(x)))
        x = x.permute(0, 2, 1)
        x, _ = self.lstm_enc(x)
        x, _ = self.lstm_dec(x)
        x = x.permute(0, 2, 1)
        x = self.conv2(self.upsample(x))
        x = x.permute(0, 2, 1)
        return x

# ==========================================
# 2. CONFIG
# ==========================================
MODEL_PATH = "models/ecg_bilstm_autoencoder.pth"
BROKER = "127.0.0.1"
TOPIC_INPUT = "ioht/ecg"
TOPIC_ALERT = "ioht/alert"
device = torch.device("cpu")
data_buffer = []

# Calibration
CALIBRATION_MODE = True
calibration_losses = []
DYNAMIC_THRESHOLD = 0.05 

# Load Model
try:
    model = BiLSTM_Autoencoder()
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()
    print("🧠 AI Model Loaded.")
except Exception as e:
    print(f"❌ Model Error: {e}")
    sys.exit(1)

# ==========================================
# 3. GENERIC ANOMALY LOGIC
# ==========================================
def analyze_window(window):
    arr = np.array(window)
    min_val = np.min(arr)
    max_val = np.max(arr)
    amplitude = max_val - min_val
    
    # ------------------------------------------------
    # GUARD 1: FLATLINE (Covers DoS)
    # ------------------------------------------------
    if amplitude < 0.05: 
        return 10.0, "Critical Signal Loss" # Generic Physical Description
        
    # ------------------------------------------------
    # GUARD 2: HIGH NOISE (Covers ARP, Smurf, Scan)
    # ------------------------------------------------
    diffs = np.abs(np.diff(arr))
    total_travel = np.sum(diffs)
    safe_amp = amplitude if amplitude > 0.5 else 1.0
    noise_ratio = total_travel / safe_amp
    
    if noise_ratio > 12.0:
        return 8.0, "Signal Interference" # Generic Physical Description

    # ------------------------------------------------
    # GUARD 3: AI SHAPE CHECK (Covers Subtle Hacks)
    # ------------------------------------------------
    try:
        denom = max_val - min_val if (max_val - min_val) > 0 else 1.0
        norm_window = (arr - min_val) / denom
        tensor_data = torch.tensor(norm_window, dtype=torch.float32).view(1, 140, 1).to(device)
        with torch.no_grad():
            reconstruction = model(tensor_data)
            loss = torch.mean(torch.abs(tensor_data - reconstruction)).item()
        return loss, "Physiological Anomaly"
    except:
        return 0.0, "Error"

# ==========================================
# 4. MQTT LOGIC
# ==========================================
def on_message(client, userdata, msg):
    global data_buffer, CALIBRATION_MODE, DYNAMIC_THRESHOLD
    try:
        payload = json.loads(msg.payload.decode())
        data_buffer.append(payload['ecg_value'])
        
        if len(data_buffer) > 140: data_buffer.pop(0)
        
        if len(data_buffer) == 140:
            loss, anomaly_type = analyze_window(data_buffer)
            
            # --- CALIBRATION ---
            if CALIBRATION_MODE:
                if loss >= 5.0: return # Don't calibrate on noise
                calibration_losses.append(loss)
                print(f"🔧 Calibrating... Loss: {loss:.4f}")
                
                if len(calibration_losses) >= 50:
                    avg = np.mean(calibration_losses)
                    std = np.std(calibration_losses)
                    DYNAMIC_THRESHOLD = max(avg + (4 * std), 0.04)
                    print(f"\n✅ CALIBRATION COMPLETE. Threshold: {DYNAMIC_THRESHOLD:.4f}\n")
                    CALIBRATION_MODE = False
                return

            # --- MONITORING ---
            # Any anomaly (Flatline, Noise, or Shape) triggers the Security System
            if loss > DYNAMIC_THRESHOLD:
                print(f"🚨 {anomaly_type}! Loss: {loss:.4f}")
                
                client.publish(TOPIC_ALERT, json.dumps({
                    "timestamp": payload['timestamp'],
                    "type": anomaly_type, # Sends physical description
                    "loss_value": loss,
                    "trigger_security": True # Tells Network AI to wake up
                }))
            else:
                print(f"\r💚 Normal | Loss: {loss:.4f}", end="")

    except Exception as e: print(f"Error: {e}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "ECG_AI_Service")
client.on_connect = lambda c,u,f,r,p: c.subscribe(TOPIC_INPUT)
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.loop_forever()