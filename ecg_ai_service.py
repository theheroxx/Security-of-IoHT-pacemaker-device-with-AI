import torch
import time
import json
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque

# ================= CONFIG =================
MODEL_PATH = "models/ecg_bilstm_autoencoder.pth"
BROKER = "127.0.0.1"
PORT = 1883

TOPIC_INPUT = ["ioht/ecg"]
TOPIC_ALERT = "fusion/ecg_alert"

SEQ_LEN = 140
FS = 50

buffer = deque(maxlen=SEQ_LEN)

# ================= MODEL =================
class ECG_AE(torch.nn.Module):
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

model = ECG_AE()
model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
model.eval()
print("🧠 ECG AI Loaded")

# ================= CALIBRATION =================
calib_losses = []
CALIB_DONE = False
THRESHOLD = None

def normalize(x):
    return (x - np.mean(x)) / (np.std(x) + 1e-6)

# ================= DETECTION =================
def classify_attack(arr, loss):
    amp = np.max(arr) - np.min(arr)
    std = np.std(arr)

    peaks = np.where(
        (arr[1:-1] > 1.0) &
        (arr[1:-1] > arr[:-2]) &
        (arr[1:-1] > arr[2:])
    )[0]

    bpm = len(peaks) / (SEQ_LEN/FS) * 60

    if amp < 0.1:
        return "DoS / Flatline"

    if std > 2.0:
        return "Injection Attack"

    if bpm > 140:
        return "Rate Tampering"

    return "Morphology Tampering"

# ================= MQTT =================
def on_message(client, userdata, msg):
    global CALIB_DONE, THRESHOLD

    p = json.loads(msg.payload.decode())
    seg = p.get("ecg_segment", [])

    for s in seg:
        buffer.append(s)
        if len(buffer) < SEQ_LEN:
            return

        arr = normalize(np.array(buffer))
        x = torch.tensor(arr, dtype=torch.float32).view(1, SEQ_LEN, 1)

        with torch.no_grad():
            recon = model(x)
            loss = torch.mean(torch.abs(x - recon)).item()

        # -------- Calibration --------
        if not CALIB_DONE:
            calib_losses.append(loss)
            if len(calib_losses) >= 80:
                THRESHOLD = np.mean(calib_losses) + 3*np.std(calib_losses)
                CALIB_DONE = True
                print(f"\n✅ Calibrated | TH={THRESHOLD:.4f}\n")
            return

        # -------- Detection --------
        if loss > THRESHOLD:
            attack = classify_attack(arr, loss)
            print(f"\n🚨 {attack} | loss={loss:.4f}")

            client.publish(TOPIC_ALERT, json.dumps({
                "timestamp": time.time(),
                "signal_status": attack,
                "loss": loss
            }))
        else:
            print(f"\r💚 OK | loss={loss:.4f}", end="")

def on_connect(c, u, f, r, p=None):
    for t in TOPIC_INPUT:
        c.subscribe(t)

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_forever()
