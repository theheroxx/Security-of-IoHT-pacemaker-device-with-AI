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

FS = 50
SEGMENT_LEN = 50
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

# ================= ECG BASE =================
def make_heartbeat(fs):
    t = np.linspace(0, 1, fs, endpoint=False)
    beat = np.zeros_like(t)

    beat += 0.12*np.exp(-((t-0.2)/0.03)**2)       # P
    beat -= 0.15*np.exp(-((t-0.28)/0.015)**2)    # Q
    beat += 1.0*np.exp(-((t-0.30)/0.01)**2)      # R
    beat -= 0.25*np.exp(-((t-0.32)/0.02)**2)     # S
    beat += 0.35*np.exp(-((t-0.48)/0.05)**2)     # T

    return beat

heartbeat = make_heartbeat(FS)

def build_ecg(n_seconds=600, hr_mean=70):
    seq = []
    t = 0
    while t < n_seconds:
        hr = np.clip(np.random.normal(hr_mean, 5), 45, 110)
        rr = 60 / hr
        L = int(FS * rr)

        beat = np.interp(
            np.linspace(0,1,L),
            np.linspace(0,1,len(heartbeat)),
            heartbeat
        )

        # amplitude variability
        beat *= np.random.normal(1.0, 0.05)

        seq.append(beat)
        t += rr

    return np.concatenate(seq)

BASE_ECG = build_ecg()
BASE_LEN = len(BASE_ECG)

# ================= PHYSIO NOISE =================
def baseline_wander(seg):
    t = np.linspace(0, 1, len(seg))
    return seg + 0.05 * np.sin(2*np.pi*0.3*t)

def muscle_noise(seg):
    return seg + np.random.normal(0, 0.02, size=len(seg))

def normal_ecg(seg):
    out = baseline_wander(seg)
    out = muscle_noise(out)
    return out

# ================= ATTACKS =================
def dropout(seg, r=0.85):
    out = seg.copy()
    mask = np.random.rand(len(out)) < r
    out[mask] = 0.0
    return out

def spike_injection(seg):
    out = seg.copy()
    pos = np.random.randint(2, len(out)-2)
    spike = np.array([0.6, 1.2, -0.8])
    out[pos-1:pos+2] += spike * np.random.choice([1, -1])
    return out

def rate_tamper(seg):
    # mimic tachycardia: compress time
    idx = np.linspace(0, len(seg)-1, int(len(seg)*0.7))
    out = np.interp(idx, np.arange(len(seg)), seg)
    return np.pad(out, (0, len(seg)-len(out)))

def replay_attack():
    if len(replay_buffer) > 50:
        return replay_buffer[np.random.randint(0, len(replay_buffer))]
    return None

def jitter(seg, ms=100):
    shift = int((ms/1000)*FS)
    return np.roll(seg, np.random.randint(-shift, shift))

def smurf_noise(seg):
    return seg + np.random.normal(0, 0.15, size=len(seg))

def hf_scan(seg):
    hf = 0.1*np.sin(np.linspace(0, 40, len(seg)))
    return seg + hf

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

        if current_mode == "Normal":
            out = normal_ecg(seg)

        elif current_mode == "DoS":
            out = dropout(seg)

        elif current_mode == "Injection":
            out = spike_injection(seg)

        elif current_mode == "RateTamper":
            out = rate_tamper(seg)

        elif current_mode == "Replay":
            r = replay_attack()
            out = r if r is not None else seg

        elif current_mode == "ARP":
            out = jitter(seg)

        elif current_mode == "Smurf":
            out = smurf_noise(seg)

        elif current_mode == "Scan":
            out = hf_scan(seg)

        else:
            out = seg

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
