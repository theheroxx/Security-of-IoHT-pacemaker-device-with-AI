import time
import json
import numpy as np
import paho.mqtt.client as mqtt
import os

# CONFIG
BROKER = "127.0.0.1"
TOPIC_DATA = "ioht/ecg"
TOPIC_CONTROL = "simulation/master_control" # Unified Topic

current_state = "Normal"

# ECG Generation
t = np.linspace(0, 100, 50000)
base_ecg = np.sin(2 * np.pi * 1 * t) + 0.5 * np.sin(2 * np.pi * 2 * t) # Synthetic fallback

def on_connect(client, userdata, flags, rc, properties):
    print("🔌 Pacemaker Connected.")
    client.subscribe(TOPIC_CONTROL)

def on_message(client, userdata, msg):
    global current_state
    # Map the Network Attack names to Physical Effects
    cmd = msg.payload.decode()
    current_state = cmd
    print(f"⚡ Pacemaker Mode: {current_state}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Pacemaker_Device")
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.loop_start()

idx = 0
print("💓 Pacemaker Running...")
try:
    while True:
        val = base_ecg[idx % len(base_ecg)]
        
        # --- VISUAL EFFECT MAPPING ---
        if current_state == "DoS":
            # Availability Attack: Flatline
            if np.random.random() > 0.1: val = 0.0
            
        elif current_state in ["Smurf", "ARP", "Scan"]:
            # Integrity/Volume Attack: Device Stress (Noise)
            # Simulates high CPU load or electrical interference
            val += np.random.uniform(-1.5, 1.5)
            
        # Normal is just the base signal

        client.publish(TOPIC_DATA, json.dumps({
            "timestamp": time.time(),
            "ecg_value": float(val),
            "status": current_state
        }))
        
        idx += 10 # Speed up for simulation
        time.sleep(0.05)
except KeyboardInterrupt:
    client.loop_stop()