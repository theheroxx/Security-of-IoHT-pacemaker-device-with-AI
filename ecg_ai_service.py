import torch
import time
import json
import sys
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque, Counter
import hashlib

# ================= CONFIG =================
MODEL_PATH = "models/ecg_bilstm_autoencoder.pth"
BROKER = "127.0.0.1"
PORT = 1883

TOPIC_INPUT = ["ioht/ecg", "pacemaker/direct_ecg_stream"]
TOPIC_ALERT = "fusion/ecg_alert"

# CRITICAL: Must match your Simulator's FS (125 for pacemaker_direct_sim_fixed)
TARGET_FS = 125 
SEQ_LEN = 140

device = torch.device("cpu")
buffer = deque(maxlen=SEQ_LEN)

# State Management
CALIBRATION_MODE = True
calib_losses = []
AE_THRESHOLD = 0.08 
BASELINE_BPM = 75.0

# Memory for Replay Attack Detection
signature_db = deque(maxlen=200)

# Buffer for Anti-Flicker (Stability)
decision_buffer = deque(maxlen=5)

# ================= MODEL =================
class BiLSTM_Autoencoder(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = torch.nn.Conv1d(1, 32, 7, padding=3)
        self.pool = torch.nn.MaxPool1d(2)
        self.relu = torch.nn.ReLU()
        self.lstm_enc = torch.nn.LSTM(32, 64, batch_first=True, bidirectional=True)
        self.lstm_dec = torch.nn.LSTM(128, 64, batch_first=True, bidirectional=True)
        self.upsample = torch.nn.Upsample(scale_factor=2)
        self.conv2 = torch.nn.Conv1d(128, 1, 7, padding=3)

    def forward(self, x):
        x = x.permute(0, 2, 1)
        x = self.pool(self.relu(self.conv1(x)))
        x = x.permute(0, 2, 1)
        x, _ = self.lstm_enc(x)
        x, _ = self.lstm_dec(x)
        x = x.permute(0, 2, 1)
        x = self.conv2(self.upsample(x))
        return x.permute(0, 2, 1)

try:
    model = BiLSTM_Autoencoder()
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()
    print("🧠 ECG AI Loaded")
except Exception as e:
    print(f"❌ Model Error: {e}")
    sys.exit(1)

# ================= HELPERS =================
def normalize(arr):
    """Z-Score Normalization"""
    m, s = np.mean(arr), np.std(arr)
    if s < 1e-6: return arr - m
    return (arr - m) / s

def calculate_bpm(arr):
    """
    Robust BPM calculation with Noise Filtering.
    """
    # 1. Amplitude Gate: If signal is flat/noise, return valid Baseline
    amp = np.max(arr) - np.min(arr)
    if amp < 1.0: return BASELINE_BPM 

    # 2. Smoothing: Moving Average to kill high-freq noise
    # This prevents jagged noise from looking like a peak
    kernel_size = 5
    kernel = np.ones(kernel_size) / kernel_size
    smoothed = np.convolve(arr, kernel, mode='same')

    # 3. Dynamic Threshold
    # Peak must be in the top 25% of the signal's height
    # AND at least 1.5 sigma above mean
    percentile_thresh = np.percentile(smoothed, 75)
    threshold = max(percentile_thresh, 1.5)
    
    peaks = []
    last = -100
    
    for i in range(1, len(smoothed)-1):
        if smoothed[i] > threshold and \
           smoothed[i] > smoothed[i-1] and \
           smoothed[i] > smoothed[i+1]:
            
            # 4. Strict Refractory Period
            # 45 samples @ 125Hz = 0.36s.
            # Max possible detected BPM = 60/0.36 = ~166 BPM.
            # This makes it physically impossible to detect 221 BPM unless checking interval math.
            if (i - last) > 45: 
                peaks.append(i)
                last = i
    
    # Need at least 2 peaks to measure an interval
    if len(peaks) < 2: return BASELINE_BPM
    
    intervals = np.diff(peaks)
    avg_samples = np.mean(intervals)
    
    # samples / Hz = seconds per beat
    bpm = 60 / (avg_samples / TARGET_FS)
    return bpm

# ================= DIAGNOSTIC LOGIC =================
def diagnose(window, loss):
    arr = np.array(window)
    norm_arr = normalize(arr)
    amp = np.max(arr) - np.min(arr)
    
    # Calculate BPM variable here so we can return it
    current_bpm = calculate_bpm(norm_arr)

    # 1. FLATLINE CHECK (DoS)
    if amp < 0.1: 
        return "Critical Signal Loss (Flatline)", 0

    # 2. REPLAY CHECK (Signature Match)
    sig_hash = hashlib.md5(norm_arr.round(2).tobytes()).hexdigest()
    if sig_hash in signature_db:
        return "Replay Attack", current_bpm
    signature_db.append(sig_hash)

    # 3. MORPHOLOGY CHECK (Priority #1)
    if loss > AE_THRESHOLD:
        if np.max(norm_arr) > 8.0: 
            return "Voltage Injection", current_bpm
        return "Physiological Anomaly", current_bpm

    # 4. RATE CHECK (Priority #2)
    # Only check rate if Calibration is done
    if not CALIBRATION_MODE:
        # Buffer zones: 
        # Normal: 45 - 160
        # Attack: > 165 or < 40
        if current_bpm > 165: return "Rate Tampering (Tachycardia)", current_bpm
        if current_bpm < 40: return "Rate Tampering (Bradycardia)", current_bpm

    return "Normal", current_bpm

# ================= MQTT LOOP =================
processed_samples = 0
INFERENCE_STRIDE = 10 # Optimization

def on_message(client, userdata, msg):
    global CALIBRATION_MODE, AE_THRESHOLD, BASELINE_BPM, processed_samples
    
    try:
        pl = json.loads(msg.payload.decode())
        seg = pl.get("ecg_segment") or pl.get("ecg_value")
        if not isinstance(seg, list): seg = [seg]

        for val in seg:
            buffer.append(float(val))
            processed_samples += 1
            
            if len(buffer) == SEQ_LEN and (processed_samples % INFERENCE_STRIDE == 0):
                
                # 1. Run AI
                norm = normalize(np.array(buffer))
                t = torch.tensor(norm, dtype=torch.float32).view(1, SEQ_LEN, 1)
                with torch.no_grad():
                    recon = model(t)
                    loss = torch.mean(torch.abs(t - recon)).item()

                # 2. Calibration
                if CALIBRATION_MODE:
                    if loss < 2.0:
                        calib_losses.append(loss)
                    if len(calib_losses) > 50:
                        avg = np.mean(calib_losses)
                        std = np.std(calib_losses)
                        AE_THRESHOLD = max(avg + (4 * std), 0.08)
                        print(f"\n✅ CALIBRATED. Threshold: {AE_THRESHOLD:.4f}")
                        CALIBRATION_MODE = False
                    else:
                        print(f"\r🔧 Calibrating... {loss:.4f}", end="")
                    continue 

                # 3. Diagnose (Now returns status AND bpm)
                status, bpm_val = diagnose(buffer, loss)
                
                # 4. Anti-Flicker
                decision_buffer.append(status)
                cnt = Counter(decision_buffer)
                final_status, count = cnt.most_common(1)[0]
                
                if "Critical" in final_status: pass 
                elif count < 4: final_status = "Normal"

                # 5. Report & LOGGING
                if final_status != "Normal":
                    # Show the BPM that triggered the alert
                    print(f"🚨 {final_status} | Loss: {loss:.3f} | BPM: {bpm_val:.0f}")
                    
                    client.publish(TOPIC_ALERT, json.dumps({
                        "timestamp": time.time(),
                        "signal_status": final_status,
                        "loss": loss,
                        "device_id": pl.get("device_id", "unknown"),
                        "bpm_est": bpm_val  # Send BPM to dashboard
                    }))
                else:
                    # Show BPM for Normal signals too (Debug)
                    AE_THRESHOLD = 0.999 * AE_THRESHOLD + 0.001 * (loss + 0.05)
                    print(f"\r💚 Normal | Loss: {loss:.3f} | BPM: {bpm_val:.0f}", end="")

    except Exception as e:
        print(f"Err: {e}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "ECG_AI_Optimized")
client.on_connect = lambda c,u,f,r,p: c.subscribe([(t,0) for t in TOPIC_INPUT])
client.on_message = on_message
client.connect(BROKER, PORT)
print("👀 ECG AI Sentinel Running...")
client.loop_forever()