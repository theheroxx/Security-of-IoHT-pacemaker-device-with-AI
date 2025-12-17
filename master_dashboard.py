import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import queue
import random
import numpy as np
import pandas as pd

# ==========================================
# 1. SETUP
# ==========================================
st.set_page_config(page_title="IoHT Command Center", layout="wide")
st.title("🏥 IoHT Command Center: Integrated Security Simulation")

# State
if "ecg_data" not in st.session_state: st.session_state.ecg_data = []
if "network_labels" not in st.session_state: st.session_state.network_labels = []  # List of recent labels for stats
if "alert_state" not in st.session_state: 
    st.session_state.alert_state = "Secure" 
if "ecg_msg" not in st.session_state: st.session_state.ecg_msg = "Normal Sinus Rhythm"
if "sec_msg" not in st.session_state: st.session_state.sec_msg = "Monitoring..."
if "last_msg_time" not in st.session_state: st.session_state.last_msg_time = 0.0
if "last_update_time" not in st.session_state: st.session_state.last_update_time = 0.0
if "stop_update" not in st.session_state: st.session_state.stop_update = False

@st.cache_resource
def get_queue(): return queue.Queue()
gui_queue = get_queue()

# ==========================================
# 2. MQTT
# ==========================================
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        gui_queue.put({"topic": msg.topic, "data": payload})
    except: pass

@st.cache_resource
def start_mqtt():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Master_Dashboard")
    client.on_message = on_message
    try:
        client.connect("127.0.0.1", 1883, 60)
        client.subscribe([("ioht/ecg", 0), ("ioht/network/data", 0)])
        client.loop_start()
    except: st.error("MQTT Error")
    return client

client = start_mqtt()

# ==========================================
# 3. CONTROLS
# ==========================================
st.sidebar.header("🕹️ Scenario Injector")
def send(cmd): 
    client.publish("simulation/master_control", cmd)
    if cmd == "Normal":
        st.session_state.alert_state = "Secure"
        st.session_state.ecg_msg = "Resetting..."
        st.session_state.sec_msg = "Resetting..."
        st.session_state.network_labels = []

if st.sidebar.button("✅ Normal", use_container_width=True): send("Normal")
st.sidebar.markdown("---")
if st.sidebar.button("🔥 DoS Attack", use_container_width=True): send("DoS")
if st.sidebar.button("🌊 Smurf Attack", use_container_width=True): send("Smurf")
if st.sidebar.button("🕵️ ARP Spoofing", use_container_width=True): send("ARP")
if st.sidebar.button("📡 Port Scan", use_container_width=True): send("Scan")
if st.sidebar.button("💉 Injection", use_container_width=True): send("Injection")
if st.sidebar.button("🔄 Replay", use_container_width=True): send("Replay")
if st.sidebar.button("⚡ Pacing Compromise", use_container_width=True): send("PacingCompromise")

st.sidebar.markdown("---")
if st.sidebar.button("🛑 Stop Updates"): 
    st.session_state.stop_update = True
if st.sidebar.button("▶️ Resume Updates"): 
    st.session_state.stop_update = False

# ==========================================
# 4. DASHBOARD UI
# ==========================================
col1, col2 = st.columns([3, 1])
with col1:
    st.subheader("💓 Live ECG Signal")
    ecg_chart = st.empty()
with col2:
    st.subheader("System Status")
    status_box = st.empty()

st.markdown("---")
col_net, col_stats = st.columns([3, 1])
with col_net:
    st.subheader("📊 Network Traffic Features (Latest Packet)")
    net_chart = st.empty()
with col_stats:
    st.subheader("Network Stats")
    stats_box = st.empty()

st.markdown("---")
st.subheader("🛡️ Security Forensics")
c1, c2, c3 = st.columns(3)
with c1: 
    st.info("Physical Layer (ECG AI)")
    ecg_box = st.empty()
with c2: 
    st.warning("Network Layer (Traffic)")
    net_box = st.empty()
with c3: 
    st.error("Diagnosis (Hybrid AI)")
    diag_box = st.empty()

# ==========================================
# 5. EVENT LOOP
# ==========================================
UPDATE_INTERVAL = 0.05  # Reduced for smoother updates, like old code
SMOOTH_WINDOW = 3  # Smaller window to reduce computation
MAX_ECG_POINTS = 2000  # Balance history and performance

while not st.session_state.stop_update:
    updated = False
    # --- Process Messages ---
    while not gui_queue.empty():
        msg = gui_queue.get()
        topic = msg['topic']
        payload = msg['data']
        updated = True
        
        # 1. ECG Signal
        if topic == "ioht/ecg":
            segment = payload.get('ecg_segment', [])
            st.session_state.ecg_data.extend(segment)
            if len(st.session_state.ecg_data) > MAX_ECG_POINTS:
                st.session_state.ecg_data = st.session_state.ecg_data[-MAX_ECG_POINTS:]
            mode = payload.get('mode', 'Normal')
            if mode != "Normal":
                st.session_state.alert_state = "Analyzing"
                st.session_state.ecg_msg = f"⚠️ Anomalous ECG: {mode}"
                st.session_state.last_msg_time = time.time()
            else:
                st.session_state.ecg_msg = "Normal Sinus Rhythm"

        # 2. Network Data
        elif topic == "ioht/network/data":
            label = payload.get('true_label')
            features = payload.get('features', [])
            if isinstance(label, int):
                label_map = {
                    0: "Normal",
                    1: "DoS",
                    2: "ARP",
                    3: "Smurf",
                    4: "Scan"
                }
                diag = label_map.get(label, f"Unknown ({label})")
            else:
                diag = str(label)
            st.session_state.network_labels.append(diag)
            if len(st.session_state.network_labels) > 100:  # Keep last 100 for stats
                st.session_state.network_labels = st.session_state.network_labels[-100:]
            if diag == "Normal":
                st.session_state.sec_msg = "Traffic Normal"
            else:
                st.session_state.alert_state = "Attack Detected"
                st.session_state.sec_msg = f"🚨 {diag} ({random.uniform(0.8, 1.0):.1%})"
                st.session_state.last_msg_time = time.time()
            # Store latest features for plotting
            if features:
                st.session_state.latest_features = np.ravel(np.array(features))  # Use ravel to flatten safely

    # --- Watchdog ---
    if st.session_state.alert_state != "Secure":
        if time.time() - st.session_state.last_msg_time > 3.0:
            st.session_state.alert_state = "Secure"
            st.session_state.ecg_msg = "Normal Rhythm"
            st.session_state.sec_msg = "Monitoring..."
            st.session_state.network_labels = []

    # --- Render UI if updated or periodically ---
    current_time = time.time()
    if updated or (current_time - st.session_state.last_update_time > UPDATE_INTERVAL):
        # ECG Chart with light smoothing
        if st.session_state.ecg_data:
            ecg_array = np.array(st.session_state.ecg_data)
            if len(ecg_array) > SMOOTH_WINDOW:
                smoothed = np.convolve(ecg_array, np.ones(SMOOTH_WINDOW)/SMOOTH_WINDOW, mode='valid')
            else:
                smoothed = ecg_array
            ecg_df = pd.DataFrame({'ECG': smoothed})
            ecg_chart.line_chart(ecg_df, height=250, use_container_width=True)

        # Network Features Chart
        if 'latest_features' in st.session_state:
            features_array = st.session_state.latest_features
            if features_array.ndim == 1 and len(features_array) > 0:
                feat_df = pd.DataFrame({'Features': features_array})
                net_chart.bar_chart(feat_df, height=250, use_container_width=True)
            else:
                net_chart.write("No valid network features to display.")

        # Network Stats
        if st.session_state.network_labels:
            label_counts = pd.Series(st.session_state.network_labels).value_counts()
            stats_box.write(label_counts)
        else:
            stats_box.write("No recent traffic.")

        # Dynamic Status
        if st.session_state.alert_state == "Secure":
            status_box.success("✅ SYSTEM SECURE")
            ecg_box.success(st.session_state.ecg_msg)
            net_box.info("Traffic Flow: Normal")
            diag_box.success(st.session_state.sec_msg)
        elif st.session_state.alert_state == "Analyzing":
            status_box.warning("⚠️ ANOMALY DETECTED")
            ecg_box.error(st.session_state.ecg_msg)
            net_box.warning("⚡ Analyzing Packets...")
            diag_box.info("Waiting for Network AI...")
        else:
            status_box.error("🚨 CYBER ATTACK CONFIRMED")
            ecg_box.error(st.session_state.ecg_msg)
            net_box.error("Traffic Anomaly Found")
            diag_box.error(st.session_state.sec_msg)

        st.session_state.last_update_time = current_time

    time.sleep(UPDATE_INTERVAL)