import time, json, numpy as np, random, os
import paho.mqtt.client as mqtt

# Config
BROKER = "127.0.0.1"
TOPIC_DATA = "ioht/network/data"
TOPIC_CONTROL = "simulation/master_control" # Matches your Dashboard
DATA_PATH = "data/ECU_ready_scientific_no_smote.npz"

# Load Data
if not os.path.exists(DATA_PATH): exit(f"Missing {DATA_PATH}")
arr = np.load(DATA_PATH, allow_pickle=True)
X, y = arr['X_test'], arr['y_test']
indices = {k: np.where(y==k)[0] for k in range(5)} # 0:Norm, 1:DoS, 2:ARP, 3:Smurf, 4:Scan

current_mode = "Normal"

def on_msg(c, u, m):
    global current_mode
    current_mode = m.payload.decode()
    print(f"⚡ Net Sim Mode: {current_mode}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Net_Gen")
client.connect(BROKER, 1883)
client.subscribe(TOPIC_CONTROL)
client.on_message = on_msg
client.loop_start()

print("🚀 Network Generator Active")
try:
    while True:
        # Map Dashboard Command -> Dataset Label
        target = 0 # Default Normal
        if current_mode == "DoS": target = 1
        elif current_mode == "ARP": target = 2
        elif current_mode == "Smurf": target = 3
        elif current_mode == "Scan": target = 4
        
        # Pick packet
        if len(indices[target]) > 0:
            idx = random.choice(indices[target])
            # Send last packet of sequence
            feats = X[idx][-1].tolist()
            
            payload = {
                "timestamp": time.time(),
                "features": feats,
                "true_label": target,
                "device": "192.168.1.105"
            }
            client.publish(TOPIC_DATA, json.dumps(payload))
        
        time.sleep(0.2)
except: client.loop_stop()