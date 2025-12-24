import time, json, numpy as np
import paho.mqtt.client as mqtt
from collections import deque

BROKER = "127.0.0.1"
TOPIC_DATA = "ioht/ecg"
TOPIC_CONTROL = "simulation/master_control"

PUBLISH_HZ = 125         
SEGMENT_LEN = 10         
DEVICE_ID = "network_gateway_01"
current_mode = "Normal"

# ---------------- CLEANER PROCEDURAL ENGINE ----------------
class HeartEngine:
    def __init__(self, fs):
        self.fs = fs
        self.buffer = deque()
        self.phase_counter = 0.0 # Keeps the sine wave smooth across chunks
        
    def generate_beat(self, target_hr=75):
        # Reduced variance (0.05 -> 0.02) for a stable, clean look
        amplitude = np.random.normal(1.0, 0.02) 
        
        # Smoother HRV (Heart Rate Variability)
        hr_varied = np.random.normal(target_hr, 1.5)
        
        samples = int(self.fs * (60.0 / hr_varied))
        t = np.linspace(0, 60.0/hr_varied, samples)
        beat = np.zeros_like(t)
        
        # Exact parameters from your "Clean" reference function:
        # P-Wave
        beat += 0.12 * np.exp(-((t-0.2)/0.03)**2)
        # Q-Wave
        beat -= 0.15 * np.exp(-((t-0.28)/0.015)**2)
        # R-Wave (Main Spike)
        beat += (1.0 * amplitude) * np.exp(-((t-0.30)/0.01)**2)
        # S-Wave
        beat -= 0.25 * np.exp(-((t-0.32)/0.02)**2)
        # T-Wave
        beat += 0.35 * np.exp(-((t-0.48)/0.05)**2)
        
        return beat.tolist()

    def get_samples(self, n):
        # 1. Fill buffer if needed
        while len(self.buffer) < n:
            self.buffer.extend(self.generate_beat(75))
            
        # 2. Extract Chunk
        chunk = []
        for _ in range(n): chunk.append(self.buffer.popleft())
        chunk = np.array(chunk)
        
        # 3. Add Continuous Baseline Wander (Breathing)
        # We use phase_counter to ensure the sine wave doesn't "jump" between chunks
        t_steps = np.arange(self.phase_counter, self.phase_counter + n)
        # Very subtle drift (0.02 amplitude) to look organic but clean
        wander = 0.02 * np.sin(2 * np.pi * 0.2 * (t_steps / self.fs))
        
        self.phase_counter += n
        
        # Return clean signal + subtle drift (No random static noise added)
        return chunk + wander

engine = HeartEngine(PUBLISH_HZ)

# ---------------- SUBTLE NETWORK ATTACKS ----------------
def apply_network_attacks(seg, mode):
    out = seg.copy()
    
    if mode == "DoS":
        # Stuttering Signal
        if np.random.rand() > 0.3: 
            return np.zeros_like(out)
            
    elif mode == "Smurf":
        # Congestion Noise
        noise = np.random.normal(0, 0.2, len(out)) 
        out = out + noise
        if np.random.rand() < 0.1: return np.zeros_like(out)

    elif mode == "ARP":
        # Jitter/Latency
        shift = np.random.randint(-3, 3)
        out = np.roll(out, shift)
        
    elif mode == "Scan":
        # Subtle Ripple
        hf = 0.08 * np.sin(np.linspace(0, 50, len(out)))
        out = out + hf

    return out

# ---------------- MQTT ----------------
def on_message(c, u, msg):
    global current_mode
    try: current_mode = msg.payload.decode()
    except: pass

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Network_Gen_Procedural")
client.on_message = on_message
client.connect(BROKER, 1883)
client.subscribe(TOPIC_CONTROL)
client.loop_start()

# ---------------- LOOP ----------------
print("🌐 Network Simulator (Clean Signal) Active...")
try:
    while True:
        if current_mode not in ["DoS", "Smurf", "ARP", "Scan"]:
            time.sleep(0.1)
            continue

        raw_seg = engine.get_samples(SEGMENT_LEN)
        final_seg = apply_network_attacks(raw_seg, current_mode)

        payload = {
            "timestamp": time.time(),
            "mode": current_mode,
            "ecg_segment": final_seg.tolist()
        }
        client.publish(TOPIC_DATA, json.dumps(payload))
        time.sleep(SEGMENT_LEN / PUBLISH_HZ)

except KeyboardInterrupt: client.loop_stop()