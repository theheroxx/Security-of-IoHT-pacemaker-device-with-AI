# ecg_attack_generator.py
import time
import json
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque

# ----------------- CONFIG -----------------
BROKER = "127.0.0.1"
PORT = 1883
TOPIC_DATA = "ioht/ecg"
TOPIC_CONTROL = "simulation/master_control"

PUBLISH_HZ = 50          # samples per second (adjust)
SEGMENT_LEN = 250        # how many samples per published segment (e.g. 5s @50Hz => 250)
DEVICE_ID = "pacemaker_sim_01"

# ----------------- MQTT -----------------
current_mode = "Normal"
replay_buffer = deque(maxlen=1000)   # store recent segments for replay attacks

def on_connect(client, userdata, flags, rc, properties=None):
    print("🔌 ECG Generator connected to broker")
    client.subscribe(TOPIC_CONTROL)

def on_message(client, userdata, msg):
    global current_mode
    try:
        cmd = msg.payload.decode()
        current_mode = cmd
        print(f"⚡ ECG Mode set to: {current_mode}")
    except Exception as e:
        print("Control parse error:", e)

client = mqtt.Client(client_id="ecg_generator")
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_start()

# ----------------- Realistic ECG baseline generator -----------------
# Build a synthetic heartbeat template (P, QRS, T) using Gaussian pulses
def make_heartbeat(fs=50, duration_s=1.0):
    t = np.linspace(0, duration_s, int(fs*duration_s), endpoint=False)
    beat = np.zeros_like(t)
    # P wave (~0.1s before QRS)
    beat += 0.1 * np.exp(-0.5*((t-0.2)/0.025)**2)
    # QRS complex (sharp)
    beat += 1.0 * np.exp(-0.5*((t-0.3)/0.01)**2)
    # small negative Q and S shoulders
    beat -= 0.15 * np.exp(-0.5*((t-0.295)/0.008)**2)
    beat -= 0.12 * np.exp(-0.5*((t-0.305)/0.008)**2)
    # T wave (later)
    beat += 0.25 * np.exp(-0.5*((t-0.45)/0.04)**2)
    return beat

FS = PUBLISH_HZ
heartbeat = make_heartbeat(fs=FS, duration_s=1.0)   # 1s heartbeat
# Build continuous ECG by repeating heartbeat with some HR variability
def build_ecg_sequence(n_seconds=300, hr_mean=60, hr_std=1.5):
    seq = []
    t = 0.0
    while t < n_seconds:
        # sample a heart rate
        hr = max(30, np.random.normal(hr_mean, hr_std))
        rr = 60.0 / hr  # seconds per beat
        # if rr != 1.0, resample heartbeat to rr length
        beat_len = int(round(FS * rr))
        beat_template = np.interp(
            np.linspace(0, 1, beat_len, endpoint=False),
            np.linspace(0, 1, len(heartbeat), endpoint=False),
            heartbeat
        )
        seq.append(beat_template)
        t += rr
    return np.concatenate(seq)

# Pre-generate a long base ECG (can be long but keep memory reasonable)
BASE_ECG = build_ecg_sequence(n_seconds=600, hr_mean=70, hr_std=2.0)  # 10 minutes
BASE_LEN = len(BASE_ECG)

# ----------------- Attack transforms on ECG -----------------
def apply_dropout(segment, drop_ratio=0.5):
    # set a fraction of samples to 0 (simulates missing signal)
    seg = segment.copy()
    mask = np.random.rand(*seg.shape) < drop_ratio
    seg[mask] = 0.0
    return seg

def apply_jitter(segment, jitter_ms=80):
    # jitter by resampling segment with random time shifts per beat-level
    seg = segment.copy()
    # apply small random shifts by circular shift
    max_shift = int(round((jitter_ms/1000.0) * FS))
    for i in range(0, len(seg), int(FS*0.5)):
        shift = np.random.randint(-max_shift, max_shift+1)
        seg[i:i+int(FS*0.5)] = np.roll(seg[i:i+int(FS*0.5)], shift)
    return seg

def apply_noise(segment, scale=0.5):
    return segment + np.random.normal(0, scale, size=segment.shape)

def apply_timewarp(segment, intensity=0.2):
    # compress / expand random subsections
    seg = segment.copy()
    L = len(seg)
    # pick a random window
    w = int(L * 0.2)
    start = np.random.randint(0, max(1,L-w))
    sub = seg[start:start+w]
    # warp factor
    factor = 1.0 + np.random.uniform(-intensity, intensity)
    newlen = max(1, int(len(sub) * factor))
    sub2 = np.interp(np.linspace(0,1,newlen), np.linspace(0,1,len(sub)), sub)
    seg = np.concatenate([seg[:start], sub2, seg[start+w:]])
    # trim/pad to original length
    if len(seg) > L:
        seg = seg[:L]
    else:
        seg = np.pad(seg, (0, L-len(seg)), 'constant')
    return seg

def inject_pacing_spikes(segment, spike_interval_s=1.0):
    seg = segment.copy()
    interval_samples = int(spike_interval_s * FS)
    for i in range(0, len(seg), interval_samples):
        if i < len(seg):
            seg[i] += 2.0  # a sharp spike
    return seg

# Replay: get recent segment from buffer
def do_replay():
    if len(replay_buffer) > 0:
        return np.array(replay_buffer[np.random.randint(0, len(replay_buffer))])
    return None

# ----------------- Main loop: publish segments -----------------
ptr = 0
print("💓 ECG attack generator running...")
try:
    while True:
        # build segment from BASE_ECG
        seg = np.zeros(SEGMENT_LEN, dtype=float)
        for i in range(SEGMENT_LEN):
            seg[i] = BASE_ECG[(ptr + i) % BASE_LEN]
        ptr = (ptr + SEGMENT_LEN) % BASE_LEN

        # default processing (normal)
        mode = current_mode

        # Map modes to transforms:
        if mode == "Normal":
            out_seg = seg
        elif mode == "DoS":
            # heavy dropout (availability loss)
            out_seg = apply_dropout(seg, drop_ratio=0.85)
        elif mode == "ARP":
            # jitter + occasional small dropout
            out_seg = apply_jitter(seg, jitter_ms=120)
            out_seg = apply_dropout(out_seg, drop_ratio=0.05)
        elif mode == "Smurf":
            # heavy noise + intermittent dropout
            out_seg = apply_noise(seg, scale=0.6)
            out_seg = apply_dropout(out_seg, drop_ratio=0.2)
        elif mode == "Scan":
            # low-amplitude high-frequency noise
            hf = np.random.normal(0, 0.2, size=seg.shape) * np.sin(np.linspace(0,50,seg.shape[0]))
            out_seg = seg + hf
        elif mode == "Injection":
            # synthetic frames inserted (non-physiological)
            out_seg = seg.copy()
            # replace random block with constant or random noise
            s = np.random.randint(0, SEGMENT_LEN//2)
            l = np.random.randint(10, SEGMENT_LEN//3)
            out_seg[s:s+l] = np.random.uniform(-2, 2, size=l)
        elif mode == "Replay":
            r = do_replay()
            out_seg = r if r is not None else seg
        elif mode == "PacingCompromise":
            # attacker changed pacing rate → insert pacing spikes at higher rate
            out_seg = inject_pacing_spikes(seg, spike_interval_s=0.5)
        else:
            out_seg = seg

        # store in replay buffer (for Replay mode)
        replay_buffer.append(out_seg.copy())

        payload = {
            "device_id": DEVICE_ID,
            "timestamp": time.time(),
            "mode": current_mode,
            # publish as list (segment)
            "ecg_segment": out_seg.tolist()
        }

        client.publish(TOPIC_DATA, json.dumps(payload))
        # maintain publish rate
        time.sleep(SEGMENT_LEN / PUBLISH_HZ)
except KeyboardInterrupt:
    print("Stopping ECG generator...")
    client.loop_stop()
