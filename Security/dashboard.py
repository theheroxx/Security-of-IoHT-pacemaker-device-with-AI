import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import queue
import pandas as pd
import datetime

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
st.set_page_config(page_title="IoHT Security Center", layout="wide")
st.title("🛡️ IoHT Network Security Center")

# Create a thread-safe Queue to hold incoming data
@st.cache_resource
def get_queue():
    return queue.Queue()

gui_queue = get_queue()

# Initialize Session State for Data History
if "traffic_history" not in st.session_state:
    # DataFrame to hold the last 100 packets
    st.session_state.traffic_history = pd.DataFrame(columns=["Timestamp", "Diagnosis", "Confidence", "Is_Attack"])

if "chart_data" not in st.session_state:
    # List to hold data for the line chart
    st.session_state.chart_data = pd.DataFrame(columns=["Confidence"])

# ==========================================
# 2. MQTT LISTENER
# ==========================================
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        gui_queue.put(payload)
    except Exception as e:
        print(f"Error parsing MQTT: {e}")

@st.cache_resource
def start_mqtt():
    # Uses Paho v2.0 callback version
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Dashboard_GUI")
    client.on_message = on_message
    try:
        client.connect("127.0.0.1", 1883, 60)
        client.subscribe("ioht/network/result")
        client.loop_start()
        print("✅ Dashboard connected to MQTT.")
    except Exception as e:
        print(f"❌ Connection Failed: {e}")
    return client

client = start_mqtt()

# ==========================================
# 3. DASHBOARD LAYOUT
# ==========================================

# --- Sidebar: Attack Controls ---
st.sidebar.header("🎮 Attack Controls")
st.sidebar.info("Click to inject traffic into the simulation.")
if st.sidebar.button("✅ Normal Traffic", use_container_width=True):
    client.publish("simulation/network_control", "Normal")
if st.sidebar.button("🔥 DoS Attack", use_container_width=True):
    client.publish("simulation/network_control", "DoS")
if st.sidebar.button("🕵️ ARP Spoofing", use_container_width=True):
    client.publish("simulation/network_control", "ARP")
if st.sidebar.button("🌊 Smurf Attack", use_container_width=True):
    client.publish("simulation/network_control", "Smurf")
if st.sidebar.button("📡 Port Scan", use_container_width=True):
    client.publish("simulation/network_control", "Scan")

# --- Main Area: Metrics ---
col1, col2, col3 = st.columns(3)
with col1:
    metric_status = st.empty()
with col2:
    metric_count = st.empty()
with col3:
    metric_last = st.empty()

st.markdown("---")

# --- Main Area: Visualization ---
col_chart, col_log = st.columns([2, 1])

with col_chart:
    st.subheader("📈 Live Threat Confidence")
    chart_placeholder = st.empty()

with col_log:
    st.subheader("📝 Traffic Logs")
    log_placeholder = st.empty()

# ==========================================
# 4. MAIN UPDATE LOOP
# ==========================================
while True:
    # Process all new messages in the queue
    while not gui_queue.empty():
        data = gui_queue.get()
        
        # 1. Format Data
        timestamp = datetime.datetime.fromtimestamp(data['timestamp']).strftime('%H:%M:%S')
        diagnosis = data['diagnosis']
        confidence = data['confidence']
        is_attack = data['is_attack']
        
        # 2. Add to History (For Table)
        new_row = {
            "Timestamp": timestamp,
            "Diagnosis": diagnosis,
            "Confidence": confidence,
            "Is_Attack": "🔴" if is_attack else "🟢"
        }
        # Append to dataframe and keep last 20 rows for clean display
        st.session_state.traffic_history = pd.concat([
            pd.DataFrame([new_row]), 
            st.session_state.traffic_history
        ]).head(20) # Show latest 20 packets
        
        # 3. Add to Chart Data (For Line Chart)
        # We plot "Confidence" as the Y-axis. 
        # If it's an attack, we keep it positive. If Normal, maybe simpler visualization?
        # Let's just plot the raw confidence of the prediction.
        new_chart_point = {"Confidence": confidence if is_attack else 0.0}
        st.session_state.chart_data = pd.concat([
            st.session_state.chart_data, 
            pd.DataFrame([new_chart_point])
        ]).tail(100) # Keep last 100 points for the chart window

    # --- Render Updates ---
    
    # 1. Metrics
    latest = st.session_state.traffic_history.iloc[0] if not st.session_state.traffic_history.empty else None
    
    if latest is not None:
        status_color = "off" if latest["Diagnosis"] == "Normal" else "inverse"
        
        if latest["Diagnosis"] == "Normal":
            metric_status.success(f"Status: Secure")
        else:
            metric_status.error(f"Status: {latest['Diagnosis']} DETECTED")
            
        metric_count.metric("Packets Analyzed", len(st.session_state.chart_data))
        metric_last.metric("Latest Confidence", f"{latest['Confidence']:.2f}")

    # 2. Line Chart (The Traffic Visualizer)
    # This creates a scrolling "heartbeat" of the network attacks
    chart_placeholder.line_chart(st.session_state.chart_data, y="Confidence", height=300)

    # 3. Data Table (The Log)
    # Display the dataframe as a clean interactive table
    log_placeholder.dataframe(
        st.session_state.traffic_history, 
        use_container_width=True,
        hide_index=True
    )

    # Refresh rate
    time.sleep(0.1)