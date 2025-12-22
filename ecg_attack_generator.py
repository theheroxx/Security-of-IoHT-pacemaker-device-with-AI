import time
import json
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque

# ================= CONFIG =================
BROKER = "127.0.0.1"
PORT = 1883

TOPIC_DATA = "ioht/ecg"
TOPIC_CONTROL = "simulation/master_control"

FS = 50                     # Sampling rate
SEGMENT_LEN = 50            # 1 second per packet
DEVICE_ID = "pacemaker_sim_01"

# ================= MQTT =================
current_mode = "Normal"
replay_buffer = deque(maxlen=2000)

def on_connect(client, userdata, flags, rc, properties=None):
    print("🔌 ECG Generator Connected")
    client.subscribe(TOPIC_CONTROL)

def on_message(client, userdata, msg):
    global current_mode
    current_mode = msg.payload.decode()
    print(f"⚡ Mode set to: {current_mode}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_start()

# ================= ECG BASELINE =================
def make_heartbeat(fs):
    t = np.linspace(0, 1, fs, endpoint=False)
    beat = np.zeros_like(t)
    beat += 0.1*np.exp(-((t-0.2)/0.025)**2)     # P
    beat += 1.0*np.exp(-((t-0.3)/0.01)**2)      # R
    beat -= 0.15*np.exp(-((t-0.295)/0.008)**2)  # Q
    beat -= 0.12*np.exp(-((t-0.305)/0.008)**2)  # S
    beat += 0.25*np.exp(-((t-0.45)/0.04)**2)    # T
    return beat

heartbeat = make_heartbeat(FS)

def build_ecg(n_seconds=600, hr_mean=70):
    seq = []
    t = 0
    while t < n_seconds:
        hr = max(40, np.random.normal(hr_mean, 2))
        rr = 60/hr
        L = int(FS * rr)
        beat = np.interp(
            np.linspace(0,1,L),
            np.linspace(0,1,len(heartbeat)),
            heartbeat
        )
        seq.append(beat)
        t += rr
    return np.concatenate(seq)

BASE_ECG = build_ecg()
BASE_LEN = len(BASE_ECG)

# ================= ATTACKS =================
def dropout(seg, r=0.8):
    m = np.random.rand(len(seg)) < r
    out = seg.copy()
    out[m] = 0.0
    return out

def spike_injection(seg):
    out = seg.copy()
    pos = np.random.randint(0, len(out))
    out[pos] += np.random.choice([3.5, -3.5])
    return out

def rate_tamper(seg):
    out = seg.copy()
    out *= 1.3
    for i in range(0, len(out), int(0.4*FS)):
        out[i] += 2.5
    return out

def replay_attack():
    if len(replay_buffer) > 10:
        return replay_buffer[np.random.randint(0, len(replay_buffer))] + 0.01
    return None

# ================= MAIN LOOP =================
ptr = 0
print("💓 ECG Generator Running")

try:
    while True:
        seg = BASE_ECG[ptr:ptr+SEGMENT_LEN]
        if len(seg) < SEGMENT_LEN:
            seg = np.pad(seg, (0, SEGMENT_LEN-len(seg)))
        ptr = (ptr + SEGMENT_LEN) % BASE_LEN

        replay_buffer.append(seg.copy())
        out = seg.copy()

        if current_mode == "DoS":
            out = dropout(seg)

        elif current_mode == "Injection":
            out = spike_injection(seg)

        elif current_mode == "RateTamper":
            out = rate_tamper(seg)

        elif current_mode == "Replay":
            r = replay_attack()
            if r is not None:
                out = r

        payload = {
            "device_id": DEVICE_ID,
            "timestamp": time.time(),
            "attack_mode": current_mode,
            "ecg_segment": out.tolist(),
            "sampling_rate": FS
        }

        client.publish(TOPIC_DATA, json.dumps(payload))
        time.sleep(SEGMENT_LEN / FS)

except KeyboardInterrupt:
    client.loop_stop()
    print("Stopped ECG Generator")
