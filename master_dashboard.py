import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import queue

# ==========================================
# 1. SETUP
# ==========================================
st.set_page_config(page_title="IoHT Command Center", layout="wide")
st.title("🏥 IoHT Command Center: Integrated Security Simulation")

# State
if "ecg_data" not in st.session_state: st.session_state.ecg_data = [0.0] * 300
if "alert_state" not in st.session_state: 
    # Holds the current system state: "Secure", "Analyzing", "Attack Detected"
    st.session_state.alert_state = "Secure" 
if "ecg_msg" not in st.session_state: st.session_state.ecg_msg = "Normal Sinus Rhythm"
if "sec_msg" not in st.session_state: st.session_state.sec_msg = "Monitoring..."
if "last_msg_time" not in st.session_state: st.session_state.last_msg_time = 0.0

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
        client.subscribe([("ioht/ecg", 0), ("ioht/alert", 0), ("ioht/network/result", 0)])
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
    # Visual feedback in UI immediately
    if cmd == "Normal":
        st.session_state.alert_state = "Secure"
        st.session_state.ecg_msg = "Resetting..."
        st.session_state.sec_msg = "Resetting..."

if st.sidebar.button("✅ Normal", use_container_width=True): send("Normal")
st.sidebar.markdown("---")
if st.sidebar.button("🔥 DoS Attack", use_container_width=True): send("DoS")
if st.sidebar.button("🌊 Smurf Attack", use_container_width=True): send("Smurf")
if st.sidebar.button("🕵️ ARP Spoofing", use_container_width=True): send("ARP")
if st.sidebar.button("📡 Port Scan", use_container_width=True): send("Scan")

# ==========================================
# 4. DASHBOARD UI
# ==========================================
col1, col2 = st.columns([3, 1])
with col1:
    st.subheader("💓 Live ECG")
    chart = st.empty()
with col2:
    st.subheader("System Status")
    status_box = st.empty()
    
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
while True:
    # --- Process Messages ---
    while not gui_queue.empty():
        msg = gui_queue.get()
        topic = msg['topic']
        payload = msg['data']
        
        # 1. ECG Signal (Always update)
        if topic == "ioht/ecg":
            st.session_state.ecg_data.append(payload['ecg_value'])
            if len(st.session_state.ecg_data) > 300: st.session_state.ecg_data.pop(0)

        # 2. ECG Alert (Triggered by Pacemaker Noise/Flatline)
        elif topic == "ioht/alert":
            st.session_state.alert_state = "Analyzing" # Yellow state
            st.session_state.ecg_msg = f"⚠️ {payload['type']}"
            st.session_state.last_msg_time = time.time()

        # 3. Security Result (Final Diagnosis from Network AI)
        elif topic == "ioht/network/result":
            diagnosis = payload['diagnosis']
            confidence = payload.get('confidence', 0.0)
            
            if diagnosis == "Normal":
                st.session_state.sec_msg = "Traffic Normal"
            else:
                st.session_state.alert_state = "Attack Detected" # Red state
                st.session_state.sec_msg = f"🚨 {diagnosis} ({confidence:.1%})"
            
            st.session_state.last_msg_time = time.time()

    # --- Watchdog (Auto-Reset to Green if silence > 3s) ---
    if st.session_state.alert_state != "Secure":
        if time.time() - st.session_state.last_msg_time > 3.0:
            st.session_state.alert_state = "Secure"
            st.session_state.ecg_msg = "Normal Rhythm"
            st.session_state.sec_msg = "Monitoring..."

    # --- Render UI ---
    chart.line_chart(st.session_state.ecg_data, height=250)
    
    # Dynamic Status Colors
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
    else: # Attack Detected
        status_box.error("🚨 CYBER ATTACK CONFIRMED")
        ecg_box.error(st.session_state.ecg_msg)
        net_box.error("Traffic Anomaly Found")
        diag_box.error(st.session_state.sec_msg)

    time.sleep(0.05)