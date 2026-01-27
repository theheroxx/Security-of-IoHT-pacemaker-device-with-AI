import torch, time, json, sys, numpy as np
import paho.mqtt.client as mqtt
from collections import deque, Counter
import hashlib

# ================= CONFIG =================
MODEL_PATH = "models/ecg_bilstm_autoencoder.pth"
BROKER = "127.0.0.1"
TOPIC_INPUT = ["ioht/ecg", "pacemaker/direct_ecg_stream"]
TOPIC_ALERT = "fusion/ecg_alert"
TARGET_FS = 125 
SEQ_LEN = 140
device = torch.device("cpu")
buffer = deque(maxlen=SEQ_LEN)
PORT=1883
# Logic State
CALIBRATION_MODE = True
calib_losses = []
AE_THRESHOLD = 0.08 
BASELINE_BPM = 75.0
replay_memory = deque(maxlen=200)
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
except: sys.exit(1)

# ================= LOGIC =================
def normalize(arr):
    m, s = np.mean(arr), np.std(arr)
    if s < 1e-6: return arr - m
    return (arr - m) / s

def calculate_bpm(arr):
    amp = np.max(arr) - np.min(arr)
    if amp < 1.0: return BASELINE_BPM 

    kernel = np.ones(5) / 5
    smoothed = np.convolve(arr, kernel, mode='same')
    
    # 75th percentile + 1.2 minimum ensures we catch R-Peaks but not noise
    threshold = max(np.percentile(smoothed, 75), 1.2)
    peaks = []
    last = -100
    
    for i in range(1, len(smoothed)-1):
        if smoothed[i] > threshold and smoothed[i] > smoothed[i-1] and smoothed[i] > smoothed[i+1]:
            # CRITICAL FIX: Refractory period lowered to 25 samples (0.2s)
            # This allows detecting up to 300 BPM without missing beats.
            if (i - last) > 25: 
                peaks.append(i)
                last = i
    
    if len(peaks) < 2: return BASELINE_BPM
    
    intervals = np.diff(peaks)
    bpm = 60 / (np.mean(intervals) / TARGET_FS)
    return bpm

def diagnose(window, loss):
    arr = np.array(window)
    norm_arr = normalize(arr)
    amp = np.max(arr) - np.min(arr)
    current_bpm = calculate_bpm(norm_arr)

    # 1. FLATLINE
    if amp < 0.1: return "Critical Signal Loss (Flatline)", 0

    # 2. REPLAY (Strict 0.05 MSE)
    is_replay = False
    if amp > 0.5:
        for saved_time, saved_sig in replay_memory:
            if (time.time() - saved_time) < 2.0: continue 
            if np.mean((norm_arr - saved_sig) ** 2) < 0.05:
                is_replay = True
                break
        if np.random.rand() < 0.05: replay_memory.append((time.time(), norm_arr))

    if is_replay: return "Replay Attack", current_bpm

    # 3. RATE CHECK (Priority)
    if not CALIBRATION_MODE:
        if current_bpm > 120: return "Rate Tampering (Tachycardia)", current_bpm
        if current_bpm < 50: return "Rate Tampering (Bradycardia)", current_bpm

    # 4. MORPHOLOGY / INJECTION
    if loss > AE_THRESHOLD:
        # Check noise level (Total Variation) to differentiate Spoof from Injection
        tv = np.sum(np.abs(np.diff(norm_arr)))
        if tv > 30.0: return "Spoofing (High Noise)", current_bpm
        if np.max(norm_arr) > 5.0: return "Voltage Injection", current_bpm
        return "Physiological Anomaly", current_bpm

    return "Normal", current_bpm

# ================= MQTT =================
processed_samples = 0
INFERENCE_STRIDE = 10 

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
                norm = normalize(np.array(buffer))
                t = torch.tensor(norm, dtype=torch.float32).view(1, SEQ_LEN, 1)
                with torch.no_grad():
                    loss = torch.mean(torch.abs(t - model(t))).item()

                if CALIBRATION_MODE:
                    if loss < 2.0: calib_losses.append(loss)
                    if len(calib_losses) > 50:
                        AE_THRESHOLD = max(np.mean(calib_losses) + 4 * np.std(calib_losses), 0.08)
                        print(f"\n✅ CALIBRATED. Threshold: {AE_THRESHOLD:.4f}")
                        CALIBRATION_MODE = False
                    else: print(f"\r🔧 Calibrating... {loss:.4f}", end="")
                    continue 

                status, bpm_val = diagnose(buffer, loss)
                decision_buffer.append(status)
                final_status = Counter(decision_buffer).most_common(1)[0][0]
                if "Critical" not in final_status and decision_buffer.count("Normal") >= 2:
                    final_status = "Normal"

                if final_status != "Normal":
                    print(f"🚨 {final_status} | BPM: {bpm_val:.0f} | Loss: {loss:.3f}")
                    client.publish(TOPIC_ALERT, json.dumps({
                        "timestamp": time.time(), "signal_status": final_status,
                        "loss": loss, "bpm_est": bpm_val
                    }))
                else:
                    AE_THRESHOLD = 0.999 * AE_THRESHOLD + 0.001 * (loss + 0.05)
                    print(f"\r💚 Normal | BPM: {bpm_val:.0f} | Loss: {loss:.3f}", end="")

    except Exception as e: print(e)

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "ECG_AI_Optimized")
client.on_connect = lambda c,u,f,r,p: c.subscribe([(t,0) for t in TOPIC_INPUT])
client.on_message = on_message
client.connect(BROKER, PORT)
print("👀 ECG AI Sentinel Running...")
client.loop_forever()