# ecg_attack_generator.py
import time
import json
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque

# ----------------- CONFIG -----------------
BROKER = "127.0.0.1"
PORT = 1883
TOPIC_DATA = "ioht/ecg"  # Matches Dashboard
TOPIC_CONTROL = "simulation/master_control"

PUBLISH_HZ = 50          # Sampling rate (Hz)
# We send smaller chunks more often for smoother dashboard updates
SEGMENT_LEN = 50         # 50 samples = 1 second per packet
DEVICE_ID = "pacemaker_sim_01"

# ----------------- MQTT -----------------
current_mode = "Normal"
replay_buffer = deque(maxlen=2000)

def on_connect(client, userdata, flags, rc, properties=None):
    print(f"🔌 ECG Generator connected to {BROKER}")
    client.subscribe(TOPIC_CONTROL)

def on_message(client, userdata, msg):
    global current_mode
    try:
        cmd = msg.payload.decode()
        current_mode = cmd
        print(f"⚡ ECG Mode switched to: {current_mode}")
    except Exception as e:
        print("Control parse error:", e)

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_start()

# ----------------- Realistic ECG Baseline -----------------
def make_heartbeat(fs=50, duration_s=1.0):
    t = np.linspace(0, duration_s, int(fs*duration_s), endpoint=False)
    beat = np.zeros_like(t)
    # P, QRS, T wave approximations
    beat += 0.1 * np.exp(-0.5*((t-0.2)/0.025)**2) # P
    beat += 1.0 * np.exp(-0.5*((t-0.3)/0.01)**2)  # R
    beat -= 0.15 * np.exp(-0.5*((t-0.295)/0.008)**2) # Q
    beat -= 0.12 * np.exp(-0.5*((t-0.305)/0.008)**2) # S
    beat += 0.25 * np.exp(-0.5*((t-0.45)/0.04)**2)   # T
    return beat

FS = PUBLISH_HZ
heartbeat = make_heartbeat(fs=FS, duration_s=1.0) 

def build_ecg_sequence(n_seconds=300, hr_mean=60, hr_std=1.5):
    seq = []
    t = 0.0
    while t < n_seconds:
        hr = max(30, np.random.normal(hr_mean, hr_std))
        rr = 60.0 / hr
        beat_len = int(round(FS * rr))
        if beat_len > 0:
            beat_template = np.interp(
                np.linspace(0, 1, beat_len, endpoint=False),
                np.linspace(0, 1, len(heartbeat), endpoint=False),
                heartbeat
            )
            seq.append(beat_template)
        t += rr
    return np.concatenate(seq)

BASE_ECG = build_ecg_sequence(n_seconds=600, hr_mean=70, hr_std=2.0)
BASE_LEN = len(BASE_ECG)

# ----------------- Attack Transforms -----------------
def apply_dropout(segment, drop_ratio=0.5):
    seg = segment.copy()
    mask = np.random.rand(*seg.shape) < drop_ratio
    seg[mask] = 0.0
    return seg

def apply_jitter(segment, jitter_ms=80):
    seg = segment.copy()
    max_shift = int(round((jitter_ms/1000.0) * FS))
    # Apply shift to chunks to simulate latency jitter
    if max_shift > 0:
        shift = np.random.randint(-max_shift, max_shift+1)
        seg = np.roll(seg, shift)
    return seg

def apply_noise(segment, scale=0.5):
    return segment + np.random.normal(0, scale, size=segment.shape)

def inject_pacing_spikes(segment, spike_interval_s=1.0):
    seg = segment.copy()
    interval_samples = int(spike_interval_s * FS)
    for i in range(0, len(seg), interval_samples):
        if i < len(seg):
            seg[i] = 2.0 # Sharp artificial spike
    return seg

def do_replay():
    if len(replay_buffer) > 5:
        # Pick a random past segment
        return np.array(replay_buffer[np.random.randint(0, len(replay_buffer)-1)])
    return None

# ----------------- Main Loop -----------------
ptr = 0
print("💓 ECG Generator Running...")

try:
    while True:
        # 1. Get Base Segment
        seg = np.zeros(SEGMENT_LEN, dtype=float)
        for i in range(SEGMENT_LEN):
            seg[i] = BASE_ECG[(ptr + i) % BASE_LEN]
        
        # Save clean signal to buffer before modification (for Replay attack source)
        replay_buffer.append(seg.copy())
        
        ptr = (ptr + SEGMENT_LEN) % BASE_LEN
        
        # 2. Apply Attack Logic
        attack_mode = current_mode
        out_seg = seg.copy()

        if attack_mode == "Normal":
            pass # Do nothing
            
        elif attack_mode == "DoS":
            out_seg = apply_dropout(seg, drop_ratio=0.85)
            
        elif attack_mode == "ARP":
            out_seg = apply_jitter(seg, jitter_ms=150)
            
        elif attack_mode == "Smurf":
            out_seg = apply_noise(seg, scale=0.4)
            out_seg = apply_dropout(out_seg, drop_ratio=0.3)
            
        elif attack_mode == "Scan":
            # High freq ripple
            hf = np.random.normal(0, 0.1, size=seg.shape) * np.sin(np.linspace(0, 100, seg.shape[0]))
            out_seg = seg + hf
            
        elif attack_mode == "Injection":
            # Inject block of chaos
            s = np.random.randint(0, SEGMENT_LEN//2)
            l = np.random.randint(5, 20)
            out_seg[s:s+l] = np.random.uniform(-1.5, 1.5, size=l)
            
        elif attack_mode == "Replay":
            r = do_replay()
            if r is not None: out_seg = r
            
        elif attack_mode == "RateTamper":
            # Force high heart rate (Pacing Compromise)
            out_seg = inject_pacing_spikes(seg, spike_interval_s=0.4) # ~150 BPM

        # 3. Publish
        payload = {
            "device_id": DEVICE_ID,
            "timestamp": time.time(),
            "mode": attack_mode,
            "ecg_segment": out_seg.tolist(), # Sends a list of 50 floats
            "sampling_rate": FS
        }

        client.publish(TOPIC_DATA, json.dumps(payload))
        
        # 4. Wait
        time.sleep(SEGMENT_LEN / PUBLISH_HZ)

except KeyboardInterrupt:
    print("Stopping generator...")
    client.loop_stop()