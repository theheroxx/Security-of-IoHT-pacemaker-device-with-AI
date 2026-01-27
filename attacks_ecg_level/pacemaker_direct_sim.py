import time, json, numpy as np
import paho.mqtt.client as mqtt
from collections import deque

# ================= CONFIG =================
BROKER = "127.0.0.1"
TOPIC_ECG_OUT = "ioht/ecg"
TOPIC_CTRL = "simulation/master_control"
TOPIC_TELEMETRY = "pacemaker/control/telemetry"

DEVICE_ID = "pacemaker_procedural"
FS = 125       # 125Hz
SEG = 10       # Send 10 samples per packet (0.08s update)
current_attack = "Normal"

# Stores valid past data to inject during a "Replay Attack"
valid_history_buffer = deque(maxlen=FS * 5) # Store last 5 seconds

# ================= PROCEDURAL HEART ENGINE =================
class HeartEngine:
    def __init__(self, fs):
        self.fs = fs
        self.buffer = deque() # Holds upcoming samples
        self.phase = 0.0      # Current phase in the beat
        
    def generate_beat(self, target_hr):
        # randomize parameters for EVERY beat -> Uniqueness
        amplitude = np.random.normal(1.2, 0.05)
        p_width = np.random.normal(0.025, 0.002)
        qrs_width = np.random.normal(0.01, 0.001)
        
        # Calculate duration of this beat based on HR
        # Add Heart Rate Variability (HRV)
        hr_varied = np.random.normal(target_hr, 3.0)
        seconds_per_beat = 60.0 / hr_varied
        samples = int(self.fs * seconds_per_beat)
        
        t = np.linspace(0, seconds_per_beat, samples)
        beat = np.zeros_like(t)
        
        # Procedural Waveform (P-QRS-T)
        # Shift P/T waves slightly random amounts
        p_loc = 0.2 + np.random.normal(0, 0.01)
        t_loc = 0.45 + np.random.normal(0, 0.01)
        
        beat += 0.15 * np.exp(-((t-p_loc)/0.03)**2)       # P
        beat -= 0.15 * np.exp(-((t-(0.3-0.02))/0.015)**2) # Q
        beat += amplitude * np.exp(-((t-0.3)/qrs_width)**2) # R (Main spike)
        beat -= 0.30 * np.exp(-((t-(0.3+0.02))/0.02)**2)  # S
        beat += 0.35 * np.exp(-((t-t_loc)/0.05)**2)       # T
        
        return beat.tolist()

    def get_samples(self, n, attack_mode):
        # 1. Fill buffer if low
        while len(self.buffer) < n:
            # Determine HR based on Attack Mode
            target_hr = 75
            if attack_mode == "RateTamper": target_hr = 150 # Tachycardia
            
            new_beat = self.generate_beat(target_hr)
            self.buffer.extend(new_beat)
            
        # 2. Extract next chunk
        chunk = []
        for _ in range(n):
            chunk.append(self.buffer.popleft())
            
        # 3. Add Continuous Biological Noise (Baseline Wander)
        t_now = time.time()
        chunk = np.array(chunk)
        
        # Breathing drift (0.25 Hz)
        wander = 0.1 * np.sin(2 * np.pi * 0.25 * t_now)
        # Muscle noise (High freq)
        noise = np.random.normal(0, 0.03, len(chunk))
        
        return chunk + wander + noise

engine = HeartEngine(FS)

# ================= ATTACK LOGIC =================
def apply_attacks(seg, mode):
    out = seg.copy()
    
    # 1. FLATLINE (DoS simulation on physical sensor)
    if mode == "Flatline":
        return np.zeros_like(out)
    
    # 2. INJECTION (FDI)
    elif mode == "Injection":
        # Overwrite with square wave or max value
        if len(out) > 0:
            # Create a blocky artifact
            out[:] = 3.0 # Rail the sensor to max voltage
    
    # 3. SPOOFING (Noise)
    elif mode == "Spoofing":
        # Replace signal with pure static
        out = np.random.uniform(-1.5, 1.5, size=len(out))
        
    # 4. REPLAY ATTACK
    elif mode == "Replay":
        # If we have history, return old data instead of new procedural data
        if len(valid_history_buffer) > SEG:
            # Slice a chunk from history
            start_idx = np.random.randint(0, len(valid_history_buffer) - SEG)
            # Convert deque slice to array
            return np.array(list(valid_history_buffer))[start_idx : start_idx+SEG]
            
    # Note: RateTamper is handled inside the HeartEngine (HR variable)
    
    return out

# ================= MQTT =================
def on_message(c, u, msg):
    global current_attack
    try: current_attack = msg.payload.decode()
    except: pass

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Pacemaker_Procedural")
client.on_message = on_message
client.connect(BROKER, 1883)
client.subscribe(TOPIC_CTRL)
client.loop_start()

# ================= MAIN LOOP =================
print(f"💓 Procedural Pacemaker Active (Unique Beats)...")

try:
    while True:
        # Sync Check: Sleep if Network Attack is active
        # (Network attacks are handled by ecg_attack_generator.py)
        if current_attack in ["DoS", "Smurf", "ARP", "Scan"]:
            time.sleep(0.1)
            continue

        # 1. Generate Fresh Biological Signal
        raw_seg = engine.get_samples(SEG, current_attack)
        
        # 2. Save Clean Signal to History (For Replay Attack source)
        # Only save if we are currently Normal (don't save attacks to replay them)
        if current_attack == "Normal":
            valid_history_buffer.extend(raw_seg)

        # 3. Apply Destructive Attacks
        final_seg = apply_attacks(raw_seg, current_attack)

        # 4. Publish
        payload = {
            "timestamp": time.time(),
            "ecg_segment": final_seg.tolist(),
            "mode": current_attack
        }
        client.publish(TOPIC_ECG_OUT, json.dumps(payload))
        
        # Telemetry
        hr_val = 150 if current_attack == "RateTamper" else 75
        if current_attack == "Flatline": hr_val = 0
        client.publish(TOPIC_TELEMETRY, json.dumps({"hr_est": hr_val, "battery": 98.2}))

        # 5. Timing
        time.sleep(SEG / FS)

except KeyboardInterrupt: client.loop_stop()