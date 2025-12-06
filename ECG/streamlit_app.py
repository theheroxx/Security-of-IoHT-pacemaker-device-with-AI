import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import queue
import datetime

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
st.set_page_config(page_title="IoHT Monitor", layout="wide")
st.title("💓 IoHT Pacemaker & Security Monitor")

# Initialize Session State Variables
if "ecg_data" not in st.session_state:
    st.session_state.ecg_data = [0.0] * 300  # Buffer for the chart
if "status_msg" not in st.session_state:
    st.session_state.status_msg = "System Secure"
if "status_color" not in st.session_state:
    st.session_state.status_color = "success" # success (green) or error (red)
if "last_alert_time" not in st.session_state:
    st.session_state.last_alert_time = 0.0

# Create a thread-safe Queue (Persists across reruns)
@st.cache_resource
def get_data_queue():
    return queue.Queue()

data_queue = get_data_queue()

# ==========================================
# 2. MQTT BACKGROUND SERVICE
# ==========================================
def on_message(client, userdata, msg):
    try:
        # Decode and put into queue
        payload = json.loads(msg.payload.decode())
        data_queue.put({"topic": msg.topic, "payload": payload})
    except Exception as e:
        print(f"Error in MQTT callback: {e}")

@st.cache_resource
def start_mqtt_client():
    # Paho v2.0 Compatible Init
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Streamlit_Viewer_ID_" + str(time.time()))
    client.on_message = on_message
    
    try:
        client.connect("127.0.0.1", 1883, 60)
        client.subscribe([("ioht/ecg", 0), ("ioht/alert", 0)])
        client.loop_start() # Run in background thread
        print("✅ Streamlit MQTT Connected!")
    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        
    return client

# Start the client once
client = start_mqtt_client()

# ==========================================
# 3. DASHBOARD LAYOUT
# ==========================================
col1, col2 = st.columns([3, 1])

with col1:
    st.subheader("Live ECG Signal (Lead II)")
    # Placeholder for the chart
    chart_placeholder = st.empty()

with col2:
    st.subheader("Security Status")
    # Placeholders for status text
    status_placeholder = st.empty()
    debug_placeholder = st.empty()
    
    st.markdown("---")
    st.write("**Simulation Controls:**")
    
    # These buttons send commands to the Pacemaker
    if st.button("🟢 Normal"):
        client.publish("simulation/control", "Normal")
    if st.button("🔴 DoS Attack"):
        client.publish("simulation/control", "DoS")
    if st.button("☠️ Spoofing"):
        client.publish("simulation/control", "Spoofing")

# ==========================================
# 4. MAIN EVENT LOOP (The Heartbeat)
# ==========================================
# This loop keeps the script running and updates the UI
while True:
    # --- A. Process Incoming Data from Queue ---
    while not data_queue.empty():
        item = data_queue.get()
        topic = item['topic']
        data = item['payload']
        
        # 1. Handle ECG Data (Update Chart Buffer)
        if topic == "ioht/ecg":
            st.session_state.ecg_data.append(data['ecg_value'])
            if len(st.session_state.ecg_data) > 300:
                st.session_state.ecg_data.pop(0)
                
        # 2. Handle Alerts (Update Status)
        elif topic == "ioht/alert":
            st.session_state.status_msg = f"⚠️ {data['type']} (Loss: {data['loss_value']:.2f})"
            st.session_state.status_color = "error" # Red
            st.session_state.last_alert_time = time.time()

    # --- B. Auto-Reset Status Logic ---
    # If we haven't seen an alert for 1.5 seconds, reset to Green
    if time.time() - st.session_state.last_alert_time > 1.5:
        if st.session_state.status_color == "error":
            st.session_state.status_msg = "System Secure"
            st.session_state.status_color = "success" # Green

    # --- C. Update UI Components ---
    # 1. Update Chart
    chart_placeholder.line_chart(st.session_state.ecg_data)
    
    # 2. Update Status Box
    if st.session_state.status_color == "success":
        status_placeholder.success(f"🛡️ {st.session_state.status_msg}")
    else:
        status_placeholder.error(st.session_state.status_msg)
        
    # 3. Update Debug Timestamp (Shows app is alive)
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    debug_placeholder.caption(f"Last Updated: {current_time}")

    # Control frame rate (approx 10-20 FPS)
    time.sleep(0.05)