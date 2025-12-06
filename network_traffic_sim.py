import time
import json
import numpy as np
import paho.mqtt.client as mqtt
import os

BROKER = "127.0.0.1"
DATA_PATH = "data/ECU_ready_scientific_no_smote.npz" # Ensure path is correct
TOPIC_DATA = "ioht/network/data"
TOPIC_CONTROL = "simulation/master_control" # Unified Topic

# Load Data
print(f"⏳ Loading Traffic Data...")
data = np.load(DATA_PATH)
X_test = data['X_test']
y_test = data['y_test']

# Binning
library = {0: [], 1: [], 2: [], 3: [], 4: []}
for i, label in enumerate(y_test):
    library[label].append(i)

# Mapping: Name -> ID
# 0: Normal, 1: DoS, 2: ARP, 3: Smurf, 4: Scan
CMD_MAP = {"Normal": 0, "DoS": 1, "ARP": 2, "Smurf": 3, "Scan": 4}
current_mode = "Normal"

def on_message(client, userdata, msg):
    global current_mode
    current_mode = msg.payload.decode()
    print(f"📡 Traffic Mode: {current_mode}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Traffic_Sim")
client.on_connect = lambda c,u,f,r,p: c.subscribe(TOPIC_CONTROL)
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.loop_start()

print("🚀 Traffic Generator Active.")
try:
    while True:
        # Get ID from Name (Default to 0 if unknown)
        class_id = CMD_MAP.get(current_mode, 0)
        
        # Pick Packet
        indices = library[class_id]
        if indices:
            idx = np.random.choice(indices)
            packet = X_test[idx].tolist()
            
            client.publish(TOPIC_DATA, json.dumps({
                "timestamp": time.time(),
                "features": packet,
                "true_label": current_mode
            }))
        
        time.sleep(0.5) # Send 2 packets/sec
except KeyboardInterrupt:
    client.loop_stop()