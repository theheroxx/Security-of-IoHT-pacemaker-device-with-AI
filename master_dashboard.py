import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import queue
import numpy as np
import pandas as pd

# ==========================================
# 1. SETUP & STYLING
# ==========================================
st.set_page_config(page_title="IoHT Command Center", layout="wide")

# Professional Styling
st.markdown("""
    <style>
    .big-font { font-size:20px !important; font-weight: bold; }
    .status-box { padding: 15px; border-radius: 8px; text-align: center; color: white; font-weight: bold;}
    .secure { background-color: #28a745; } /* Green */
    .analyzing { background-color: #ffc107; color: black; } /* Yellow */
    .attack { background-color: #dc3545; } /* Red */
    </style>
    """, unsafe_allow_html=True)

st.title("🏥 IoHT Command Center: Hybrid Security Simulation")

# --- Session State Initialization ---
if "ecg_data" not in st.session_state: st.session_state.ecg_data = []
if "network_labels" not in st.session_state: st.session_state.network_labels = []
if "alert_state" not in st.session_state: st.session_state.alert_state = "Secure"
if "ecg_msg" not in st.session_state: st.session_state.ecg_msg = "Normal Sinus Rhythm"
if "sec_msg" not in st.session_state: st.session_state.sec_msg = "System Monitoring..."
if "pacemaker_hr" not in st.session_state: st.session_state.pacemaker_hr = 72
if "pacemaker_battery" not in st.session_state: st.session_state.pacemaker_battery = 98.0
if "last_msg_time" not in st.session_state: st.session_state.last_msg_time = 0.0
if "last_update_time" not in st.session_state: st.session_state.last_update_time = 0.0
if "stop_update" not in st.session_state: st.session_state.stop_update = False
if "latest_features" not in st.session_state: st.session_state.latest_features = np.array([])
if "ai_diagnosis" not in st.session_state: st.session_state.ai_diagnosis = "Waiting..."
if "events" not in st.session_state: st.session_state.events = []
if "current_mode" not in st.session_state: st.session_state.current_mode = "Normal"

@st.cache_resource
def get_queue(): return queue.Queue()
gui_queue = get_queue()

# ==========================================
# 2. MQTT SETUP
# ==========================================
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        gui_queue.put({"topic": msg.topic, "data": payload})
    except: pass

@st.cache_resource
def start_mqtt():
    # Paho v2.0 Compatible
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Master_Dashboard_Final")
    client.on_message = on_message
    try:
        client.connect("127.0.0.1", 1883, 60)
        # Subscribe to ALL components in the ecosystem
        client.subscribe([
            ("ioht/ecg", 0),                # ECG Data
            ("ioht/network/data", 0),       # Network Truth
            ("ioht/network/result", 0),     # Network AI
            ("fusion/ecg_alert", 0),        # ECG AI
            ("fusion/final_decision", 0),   # Fusion Engine
            ("simulation/master_control", 0), # Control Sync
            ("pacemaker/control/telemetry", 0) # Battery/HR
        ])
        client.loop_start()
    except: st.error("MQTT Connection Error: Check Mosquitto")
    return client

client = start_mqtt()

# ==========================================
# 3. CONTROLS (Unified Sidebar)
# ==========================================
st.sidebar.header("🕹️ Scenario Injector")

# Full List of Supported Attacks
ATTACK_OPTIONS = [
    "Normal", 
    "DoS", "Smurf", "ARP", "Scan",       # Network Layer
    "Injection", "Replay", "RateTamper", "Flatline", "Spoofing" # Physical Layer
]

selected_attack = st.sidebar.selectbox("Select Scenario", ATTACK_OPTIONS, index=0)

if st.sidebar.button("🚀 Inject Scenario", use_container_width=True):
    if client:
        # Broadcast command to everyone
        client.publish("simulation/master_control", selected_attack)
        
        st.session_state.current_mode = selected_attack
        
        # Immediate UI Reset for Normal
        if selected_attack == "Normal":
            st.session_state.alert_state = "Secure"
            st.session_state.ecg_msg = "Resetting..."
            st.session_state.sec_msg = "Resetting..."
            st.session_state.ai_diagnosis = "Normal"
            st.session_state.network_labels = []

st.sidebar.markdown("---")
c1, c2 = st.sidebar.columns(2)
if c1.button("🛑 Pause"): st.session_state.stop_update = True
if c2.button("▶️ Resume"): st.session_state.stop_update = False
if st.sidebar.button("🧹 Clear Logs"): st.session_state.events = []

# ==========================================
# 4. DASHBOARD LAYOUT
# ==========================================
# Row 1: ECG & Vitals
col1, col2 = st.columns([3, 1])
with col1:
    st.subheader("💓 Real-Time ECG Stream")
    ecg_chart = st.empty()
with col2:
    st.subheader("System Status")
    status_box = st.empty()
    hr_metric = st.empty()
    batt_metric = st.empty()

st.markdown("---")

# Row 2: Network & Logs
col_net, col_log = st.columns([2, 1])
with col_net:
    st.subheader("📊 Network Traffic Analysis")
    net_chart = st.empty()
with col_log:
    st.subheader("📝 Live Event Log")
    events_box = st.empty()

st.markdown("---")

# Row 3: Security Forensics
st.subheader("🛡️ Fusion Security Diagnosis")
c1, c2, c3 = st.columns(3)
with c1: 
    st.info("Physical Layer AI (ECG)")
    ecg_box = st.empty()
with c2: 
    st.warning("Network Layer AI (Traffic)")
    net_box = st.empty()
with c3: 
    st.error("Fusion Decision (Final)")
    diag_box = st.empty()

# ==========================================
# 5. MAIN LOGIC LOOP
# ==========================================
UPDATE_INTERVAL = 0.05
MAX_ECG_POINTS = 500  # Holds ~10 seconds of data

while not st.session_state.stop_update:
    updated = False
    
    # --- Process Queue ---
    while not gui_queue.empty():
        msg = gui_queue.get()
        topic = msg['topic']
        data = msg['data']
        updated = True
        
        ts = time.strftime('%H:%M:%S')

        # 1. ECG Signal (Handles both Single Points and Lists/Segments)
        if topic == "ioht/ecg":
            # Check for different possible keys from different simulator versions
            segment = data.get('ecg_segment') or data.get('ecg')
            val = data.get('ecg_value')
            
            if segment is not None and isinstance(segment, list):
                st.session_state.ecg_data.extend(segment)
            elif val is not None:
                st.session_state.ecg_data.append(val)
                
            # Limit Buffer Size
            if len(st.session_state.ecg_data) > MAX_ECG_POINTS:
                st.session_state.ecg_data = st.session_state.ecg_data[-MAX_ECG_POINTS:]

        # 2. Network Truth (Simulator) - Charts Only
        elif topic == "ioht/network/data":
            label = data.get('true_label', 0)
            # Map integers to names
            mapping = {0: "Normal", 1: "DoS", 2: "ARP", 3: "Smurf", 4: "Scan"}
            truth_label = mapping.get(label, str(label))
            
            # Store features for visualization
            if 'features' in data:
                try:
                    st.session_state.latest_features = np.array(data['features'], dtype=float).flatten()[:40]
                except: pass

        # 3. AI Prediction (Network) - Triggers Alert
        elif topic == "ioht/network/result": 
            prediction = data.get("diagnosis", "Normal")
            conf = data.get("confidence", 0.0)
            st.session_state.ai_diagnosis = prediction
            
            if prediction != "Normal":
                st.session_state.alert_state = "Attack Detected"
                st.session_state.sec_msg = f"🚨 {prediction} ({conf:.1%})"
                st.session_state.last_msg_time = time.time()
                st.session_state.events.append(f"{ts} [NET] {prediction}")
            else:
                st.session_state.sec_msg = "Traffic Normal"

        # 4. ECG AI Alerts - Triggers Alert
        elif topic in ["fusion/ecg_alert", "ioht/alert"]:
            alert_type = data.get('signal_status', 'Anomaly')
            loss = data.get('loss', 0.0)
            st.session_state.ecg_msg = f"⚠️ {alert_type} (Loss: {loss:.2f})"
            st.session_state.alert_state = "Analyzing" # Yellow alert
            st.session_state.last_msg_time = time.time()
            st.session_state.events.append(f"{ts} [PHY] {alert_type}")

        # 5. Fusion Decision - Final Authority
        elif topic == "fusion/final_decision":
            status = data.get('status', 'Normal')
            severity = data.get('severity', 'Low')
            
            if status != "Normal":
                st.session_state.alert_state = "Attack Detected"
                st.session_state.events.append(f"{ts} [FUSION] {status}")
            
            # Display text
            if status == "Normal":
                diag_box.success(f"Status: Normal")
            else:
                diag_box.error(f"{status} ({severity})")

        # 6. Telemetry & Control Sync
        elif topic == "pacemaker/control/telemetry":
            st.session_state.pacemaker_hr = float(data.get('hr_est', 72))
            st.session_state.pacemaker_battery = float(data.get('battery', 98.0))
        
        elif topic == "simulation/master_control":
             st.session_state.current_mode = data if isinstance(data, str) else msg['payload'].decode()

    # --- Watchdog (Auto Reset) ---
    if st.session_state.alert_state != "Secure":
        if time.time() - st.session_state.last_msg_time > 3.0:
            st.session_state.alert_state = "Secure"
            st.session_state.ecg_msg = "Normal Sinus Rhythm"
            st.session_state.sec_msg = "System Monitoring..."
            st.session_state.ai_diagnosis = "Normal"

    # --- Render UI ---
    current_time = time.time()
    if updated or (current_time - st.session_state.last_update_time > UPDATE_INTERVAL):
        
        # Charts
        if st.session_state.ecg_data:
            ecg_chart.line_chart(st.session_state.ecg_data, height=250)
        
        if hasattr(st.session_state, 'latest_features'):
             net_chart.bar_chart(st.session_state.latest_features, height=200)

        # Status Boxes
        if st.session_state.alert_state == "Secure":
            status_box.markdown(f'<div class="status-box secure">✅ SYSTEM SECURE</div>', unsafe_allow_html=True)
        elif st.session_state.alert_state == "Analyzing":
            status_box.markdown(f'<div class="status-box analyzing">⚠️ ANOMALY DETECTED</div>', unsafe_allow_html=True)
        else:
            status_box.markdown(f'<div class="status-box attack">🚨 ATTACK CONFIRMED</div>', unsafe_allow_html=True)

        # Metrics
        hr_metric.metric("Heart Rate", f"{st.session_state.pacemaker_hr:.0f} BPM")
        batt_metric.metric("Battery", f"{st.session_state.pacemaker_battery}%")

        # Detailed Diagnosis
        ecg_box.write(st.session_state.ecg_msg)
        net_box.write(st.session_state.sec_msg)

        # Logs
        if st.session_state.events:
            events_box.text("\n".join(st.session_state.events[-6:]))

        st.session_state.last_update_time = current_time
    
    time.sleep(UPDATE_INTERVAL)