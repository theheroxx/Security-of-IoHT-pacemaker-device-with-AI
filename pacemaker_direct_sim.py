import time
import json
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque

# ---------------- CONFIG ----------------
BROKER = "127.0.0.1"
TOPIC_ECG_OUT = "ioht/ecg"
TOPIC_CTRL = "simulation/master_control"
TOPIC_TELEMETRY = "pacemaker/control/telemetry"

DEVICE_ID = "pacemaker_v2"
FS = 125       
SEG = 50       
current_attack = "Normal"

replay_store = deque(maxlen=300)

# ---------------- ECG Generator ----------------
def make_normal_heartbeat(fs=125):
    t = np.linspace(0, 1, fs, endpoint=False)
    beat = np.zeros_like(t)
    beat += 0.1*np.exp(-((t-0.2)/0.025)**2)     # P-wave
    beat += 1.2*np.exp(-((t-0.3)/0.01)**2)      # QRS (Tall and Sharp)
    beat += 0.25*np.exp(-((t-0.45)/0.04)**2)    # T-wave
    return beat

heartbeat = make_normal_heartbeat(FS)

def build_ecg(num_seconds=600, hr=75):
    seq = []
    rr = 60.0 / hr
    beat_len = int(FS * rr)
    templ = np.interp(np.linspace(0,1,beat_len), np.linspace(0,1,len(heartbeat)), heartbeat)
    nbeats = int((num_seconds) / rr) + 1
    for _ in range(nbeats):
        seq.append(templ)
    return np.concatenate(seq)

BASE = build_ecg(num_seconds=600, hr=75)
L = len(BASE)

# ---------------- Distinct Attack Logic ----------------
def attack_rate_tamper(seg):
    # Compresses signal to simulate 150 BPM
    new_len = max(10, int(len(seg) * 0.5)) 
    idx = np.linspace(0, len(seg)-1, new_len)
    res = np.interp(idx, np.arange(len(seg)), seg)
    out = np.interp(np.linspace(0, new_len-1, len(seg)), np.arange(new_len), res)
    return out

def attack_injection(seg):
    # Electrical Interference / Square Wave
    out = seg.copy()
    # Insert 3 sharp spikes (unnatural)
    idxs = np.random.choice(len(seg), 3)
    out[idxs] = 3.0 
    return out

def attack_param_corrupt(seg):
    # Morphology Distortion (Wobble)
    # Multiplies signal by a low freq sine wave to distort shapes
    t = np.linspace(0, 4*np.pi, len(seg))
    distortion = 1.0 + 0.5 * np.sin(t)
    return seg * distortion

def attack_flatline(seg):
    return np.zeros_like(seg)

def attack_replay(seg):
    if len(replay_store) > 10:
        return np.array(replay_store[np.random.randint(0, len(replay_store)-1)])
    return seg

# ----------------- MQTT -----------------
def on_message(client, userdata, msg):
    global current_attack
    try: current_attack = msg.payload.decode()
    except: pass

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Pacemaker_Sim")
client.on_message = on_message
client.connect(BROKER, 1883)
client.subscribe(TOPIC_CTRL)
client.loop_start()

# --------------- Loop ---------------
ptr = 0
print(f"💓 Pacemaker Physics Engine Running...")

try:
    while True:
        seg = np.zeros(SEG, dtype=float)
        for i in range(SEG):
            seg[i] = BASE[(ptr + i) % L]
        ptr = (ptr + SEG) % L

        if np.random.rand() < 0.2: replay_store.append(seg.copy())

        mode = current_attack
        out = seg.copy()

        # Physical Attacks Only
        if mode == "RateTamper": out = attack_rate_tamper(seg)
        elif mode == "Injection": out = attack_injection(seg)
        elif mode == "Flatline": out = attack_flatline(seg)
        elif mode == "Replay": out = attack_replay(seg)
        elif mode == "Spoofing": out = attack_param_corrupt(seg) # Mapped to Param Corrupt

        payload = {
            "timestamp": time.time(),
            "ecg_segment": out.tolist(),
            "mode": mode
        }
        client.publish(TOPIC_ECG_OUT, json.dumps(payload))

        tel = {"device_id": DEVICE_ID, "mode": mode, "battery": 98.5, 
               "hr_est": 150 if mode == "RateTamper" else 75}
        client.publish(TOPIC_TELEMETRY, json.dumps(tel))

        time.sleep(SEG / FS)

except KeyboardInterrupt:
    client.loop_stop()