# network_attack_generator.py
import time
import json
import numpy as np
import paho.mqtt.client as mqtt
import random
from collections import deque

# ----------------- CONFIG -----------------
BROKER = "127.0.0.1"
PORT = 1883
TOPIC_DATA = "ioht/network/data"
TOPIC_CONTROL = "simulation/master_control"
DATA_PATH = "data/ECU_ready_scientific_no_smote.npz"  # adjust

PUBLISH_INTERVAL = 0.2   # base interval between packets (seconds)
DEVICE_ID = "traffic_sim_01"

# ----------------- LOAD dataset (flat features) -----------------
print("Loading dataset...", DATA_PATH)
arr = np.load(DATA_PATH, allow_pickle=True)
X_test = arr['X_test']
y_test = arr['y_test']
n_test = len(X_test)
indices_by_label = {}
for i, lab in enumerate(y_test):
    indices_by_label.setdefault(int(lab), []).append(i)

# ----------------- MQTT -----------------
current_mode = "Normal"
control_params = {
    "dos_drop_ratio": 0.5,
    "dos_flood_rate": 200,   # packets per second for flood (Smurf-like)
    "mitm_jitter_ms": 80,
    "injection_rate": 0.02,  # fraction of packets to inject modified
    "replay_prob": 0.05
}

def on_connect(c, u, flags, rc, properties=None):
    print("🔌 Traffic generator connected")
    c.subscribe(TOPIC_CONTROL)

def on_message(c, u, msg):
    global current_mode
    try:
        cmd = msg.payload.decode()
        current_mode = cmd
        print("⚡ Traffic mode:", current_mode)
    except:
        pass

client = mqtt.Client(client_id="network_generator")
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_start()

# ----------------- Attack primitives -----------------
replay_store = deque(maxlen=5000)

def send_packet(payload):
    client.publish(TOPIC_DATA, json.dumps(payload))

def mitm_modify(features):
    # small perturbation + reorder of some features to simulate tampered header/payload
    x = features.copy()
    # add jitter-like noise to timing features (if exist)
    noise = np.random.normal(0, 0.05, size=x.shape)
    x = x + noise
    # random shuffle of small subset of feature positions to simulate re-ordering
    k = max(1, int(0.01 * x.size))
    idx = np.random.choice(len(x), k, replace=False)
    x[idx] = np.random.permutation(x[idx])
    return x

def inject_packet(base_features):
    # fabricate a packet: combine base with random noise and impossible flag values
    x = base_features.copy()
    n = len(x)
    x += np.random.normal(0, 0.2, size=x.shape)
    # clamp if necessary
    return x

def replay_packet():
    if len(replay_store) == 0:
        return None
    return replay_store[np.random.randint(0, len(replay_store))]

# ----------------- Main send loop -----------------
print("🚀 Network attack generator running...")

i = 0
try:
    while True:
        if current_mode == "Normal":
            # pick random normal sample
            lab = 0
            idx = random.choice(indices_by_label.get(lab, range(n_test)))
            features = X_test[idx].astype(float)
            payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": features.tolist(), "true_label": int(y_test[idx])}
            send_packet(payload)
            replay_store.append(payload)
            time.sleep(PUBLISH_INTERVAL)

        elif current_mode == "DoS":
            # simulate packet loss at receiver: we still may send, but many are dropped.
            lab = 1  # DoS samples for semantic label may exist; but we also simulate network drop
            idx = random.choice(indices_by_label.get(lab, range(n_test)))
            features = X_test[idx].astype(float)
            # simulate that many packets are dropped: probabilistic publish
            if random.random() > control_params["dos_drop_ratio"]:
                payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": features.tolist(), "true_label": int(y_test[idx])}
                send_packet(payload)
                replay_store.append(payload)
            # also sometimes send null/heartbeat to indicate dropout:
            if random.random() < 0.02:
                send_packet({"device": DEVICE_ID, "timestamp": time.time(), "features": [], "true_label": "MISSING"})
            time.sleep(PUBLISH_INTERVAL)

        elif current_mode == "ARP":
            # MITM style: reorder and jitter timestamps
            lab = 2 if 2 in indices_by_label else 0
            idx = random.choice(indices_by_label.get(lab, range(n_test)))
            features = X_test[idx].astype(float)
            # introduce jitter by delaying publish
            jitter = np.random.normal(0, control_params["mitm_jitter_ms"] / 1000.0)
            time.sleep(max(0, jitter))
            mod = mitm_modify(features)
            payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": mod.tolist(), "true_label": int(y_test[idx])}
            send_packet(payload)
            replay_store.append(payload)
            time.sleep(PUBLISH_INTERVAL)

        elif current_mode == "Smurf":
            # flood many packets per loop to simulate amplification/flooding
            rate = control_params["dos_flood_rate"]
            lab = 3 if 3 in indices_by_label else 1
            for _ in range(max(1, int(rate/10))):  # send burst (tunable)
                idx = random.choice(indices_by_label.get(lab, range(n_test)))
                f = X_test[idx].astype(float)
                payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": f.tolist(), "true_label": int(y_test[idx])}
                send_packet(payload)
                replay_store.append(payload)
            time.sleep(0.1)

        elif current_mode == "Scan":
            # scan-like probing: many small uncertain packets (simulate low-volume but many dests)
            lab = 4 if 4 in indices_by_label else 0
            for _ in range(5):
                idx = random.choice(indices_by_label.get(lab, range(n_test)))
                f = X_test[idx].astype(float)
                # make packets smaller: send only a subset of features
                k = max(10, int(0.1 * len(f)))
                sub = f[:k]
                payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": sub.tolist(), "true_label": int(y_test[idx])}
                send_packet(payload)
                replay_store.append(payload)
            time.sleep(0.2)

        elif current_mode == "Injection":
            # occasionally inject fabricated packets
            lab = random.choice(list(indices_by_label.keys()))
            idx = random.choice(indices_by_label.get(lab, range(n_test)))
            base = X_test[idx].astype(float)
            if random.random() < control_params["injection_rate"]:
                inst = inject_packet(base)
                payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": inst.tolist(), "true_label": "INJECTED"}
                send_packet(payload)
                replay_store.append(payload)
            else:
                payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": base.tolist(), "true_label": int(y_test[idx])}
                send_packet(payload)
                replay_store.append(payload)
            time.sleep(PUBLISH_INTERVAL)

        elif current_mode == "Replay":
            # send previously stored packets from replay store
            pkt = replay_packet()
            if pkt:
                pkt2 = pkt.copy()
                pkt2["timestamp"] = time.time()
                send_packet(pkt2)
            else:
                # fallback normal
                idx = random.randrange(n_test)
                f = X_test[idx].astype(float)
                send_packet({"device": DEVICE_ID, "timestamp": time.time(), "features": f.tolist(), "true_label": int(y_test[idx])})
            time.sleep(PUBLISH_INTERVAL)

        else:
            # unknown mode -> normal
            idx = random.randrange(n_test)
            f = X_test[idx].astype(float)
            payload = {"device": DEVICE_ID, "timestamp": time.time(), "features": f.tolist(), "true_label": int(y_test[idx])}
            send_packet(payload)
            replay_store.append(payload)
            time.sleep(PUBLISH_INTERVAL)

except KeyboardInterrupt:
    print("Stopping traffic generator...")
    client.loop_stop()
