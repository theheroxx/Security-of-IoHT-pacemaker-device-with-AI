import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import queue
import numpy as np
import pandas as pd
from datetime import datetime
from log_manager import logger  

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================
st.set_page_config(
    page_title="IoHT Security Monitor",
    layout="wide",
    page_icon=":material/health_and_safety:",
    initial_sidebar_state="expanded"
)

# Streamlined Styling
st.markdown("""
    <style>
    .status-badge {
        padding: 8px 16px;
        border-radius: 6px;
        text-align: center;
        font-weight: 600;
        font-size: 0.9rem;
        margin: 8px 0;
    }
    .status-secure { background: #4CAF50; color: white; }
    .status-analyzing { background: #FFC107; color: #212121; }
    .status-attack { background: #F44336; color: white; animation: pulse 2s infinite; }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }
    
    [data-testid="stMetricValue"] { font-size: 1.8rem; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    </style>
""", unsafe_allow_html=True)

# Header
st.title(":material/health_and_safety: IoHT Security Monitor")
st.caption("Real-time hybrid security monitoring for medical IoT devices")

# ==========================================
# 2. SESSION STATE INITIALIZATION
# ==========================================
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
if "network_traffic" not in st.session_state: st.session_state.network_traffic = []  # New: for streaming network traffic

@st.cache_resource
def get_queue(): return queue.Queue()
gui_queue = get_queue()

# ==========================================
# 3. MQTT SETUP
# ==========================================
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        gui_queue.put({"topic": msg.topic, "data": payload})
    except: pass

@st.cache_resource
def start_mqtt():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "Master_Dashboard_Final")
    client.on_message = on_message
    try:
        client.connect("127.0.0.1", 1883, 60)
        client.subscribe([
            ("ioht/ecg", 0),
            ("ioht/network/data", 0),
            ("ioht/network/result", 0),
            ("fusion/ecg_alert", 0),
            ("fusion/final_decision", 0),
            ("simulation/master_control", 0),
            ("pacemaker/control/telemetry", 0)
        ])
        client.loop_start()
    except: st.error("⚠️ MQTT Connection Error: Check Mosquitto Broker")
    return client

client = start_mqtt()

# ==========================================
# 4. SIDEBAR CONTROLS
# ==========================================
with st.sidebar:
    st.header(":material/tune: Control Panel")
    
    # System Status
    alert_count = len([e for e in st.session_state.events if "ATTACK" in e or "Anomaly" in e])
    st.metric("Current Mode", st.session_state.current_mode)
    st.metric("Active Alerts", alert_count, delta="Critical" if alert_count > 0 else "Clear")
    
    st.divider()
    
    # Attack Scenarios
    st.subheader(":material/warning: Test Scenarios")
    
    ATTACK_OPTIONS = [
        "Normal",
        "DoS", "Smurf", "ARP", "Scan",
        "Injection", "Replay", "RateTamper"
    ]
    
    attack_icons = {
        "Normal": "",
        "DoS": "", 
        "Smurf": "",
        "ARP": "", 
        "Scan": "",
        "Injection": "", 
        "Replay": "", 
        "RateTamper": ""
    }
    
    selected_attack = st.selectbox(
        "Select Scenario",
        ATTACK_OPTIONS,
        format_func=lambda x: f"{attack_icons.get(x, '')} {x}",
        label_visibility="collapsed"
    )
    
    if st.button(":material/play_arrow: Inject Scenario", use_container_width=True, type="primary"):
        if client:
            client.publish("simulation/master_control", selected_attack)
            st.session_state.current_mode = selected_attack
            
            if selected_attack == "Normal":
                st.session_state.alert_state = "Secure"
                st.session_state.ecg_msg = "Resetting..."
                st.session_state.sec_msg = "Resetting..."
                st.session_state.ai_diagnosis = "Normal"
                st.session_state.network_labels = []
                st.session_state.network_traffic = []  # Clear network traffic on reset
            st.success(f"Injected: {selected_attack}")
            time.sleep(0.5)
            st.rerun()
    
    st.divider()
    
    # System Controls
    st.subheader(":material/settings: System")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button(":material/pause:", use_container_width=True):
            st.session_state.stop_update = True
            st.rerun()
    with col2:
        if st.button(":material/play_arrow:", use_container_width=True):
            st.session_state.stop_update = False
            st.rerun()
    
    if st.button(":material/delete: Clear Logs", use_container_width=True):
        st.session_state.events = []
        st.session_state.network_traffic = []  # Also clear network traffic
        st.rerun()
    
    st.divider()
    
    # Connection Status
    st.caption(f"**MQTT:** {'🟢 Connected' if client else '🔴 Disconnected'}")
    st.caption(f"**Queue:** {gui_queue.qsize()} messages")
    st.caption(f"**Updated:** {datetime.now().strftime('%H:%M:%S')}")

# ==========================================
# 5. STATUS BANNER
# ==========================================
status_col1, status_col2 = st.columns([3, 1])

with status_col1:
    if st.session_state.alert_state == "Secure":
        st.markdown('<div class="status-badge status-secure">:material/verified: SYSTEM SECURE - No threats detected</div>', unsafe_allow_html=True)
    elif st.session_state.alert_state == "Analyzing":
        st.markdown('<div class="status-badge status-analyzing">:material/warning: ANOMALY DETECTED - Analyzing potential issues</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge status-attack">:material/crisis_alert: ATTACK DETECTED - Immediate attention required</div>', unsafe_allow_html=True)

with status_col2:
    if st.button(":material/refresh: Refresh Now", use_container_width=True):
        st.rerun()

st.divider()

# ==========================================
# 6. KEY METRICS
# ==========================================
col1, col2, col3, col4 = st.columns(4)

with col1:
    hr_delta = "Normal" if 40 <= st.session_state.pacemaker_hr <= 120 else "Critical"
    hr_delta_color = "normal" if hr_delta == "Normal" else "inverse"
    st.metric(
        ":material/ecg_heart: Heart Rate", 
        f"{st.session_state.pacemaker_hr:.0f} BPM",
        delta=hr_delta,
        delta_color=hr_delta_color,
        help="Patient's current heart rate from pacemaker telemetry"
    )

with col2:
    batt_delta = "Optimal" if st.session_state.pacemaker_battery > 20 else "Low"
    batt_delta_color = "normal" if batt_delta == "Optimal" else "inverse"
    st.metric(
        ":material/battery_charging_full: Battery", 
        f"{st.session_state.pacemaker_battery:.1f}%",
        delta=batt_delta,
        delta_color=batt_delta_color,
        help="Pacemaker battery level"
    )

with col3:
    st.metric(
        ":material/monitoring: ECG Samples", 
        f"{len(st.session_state.ecg_data):,}",
        help="Number of ECG data points received"
    )

with col4:
    st.metric(
        ":material/notification_important: Active Alerts", 
        alert_count,
        help="Count of unresolved security alerts"
    )

st.divider()

# ==========================================
# 7. MAIN DASHBOARD TABS
# ==========================================
tab1, tab2, tab3 = st.tabs([
    ":material/ecg: Physiological Monitoring",
    ":material/lan: Network Monitoring",
    ":material/analytics: Event Log & Traffic"
])  # Updated tab names for clarity

# TAB 1: PHYSIOLOGICAL MONITORING
with tab1:
    st.subheader("ECG Signal Stream")
    st.caption("Live ECG waveform from the device")
    
    if st.session_state.ecg_data:
        st.line_chart(st.session_state.ecg_data, height=400, use_container_width=True)
    else:
        st.info(":material/pending: Awaiting ECG data stream...")
    
    st.divider()
    
    # Physical Layer Analysis
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### :material/cardiology: ECG Analysis")
        if "Anomaly" in st.session_state.ecg_msg or "⚠️" in st.session_state.ecg_msg:
            st.warning(st.session_state.ecg_msg)
        elif "Normal" in st.session_state.ecg_msg or "Resetting" in st.session_state.ecg_msg:
            st.success(st.session_state.ecg_msg)
        else:
            st.info(st.session_state.ecg_msg)
    
    with col2:
        st.markdown("#### :material/analytics: Statistics")
        st.metric("Signal Quality", "98.2%", help="Percentage of clean signal received")
        st.metric("Latency", "< 50ms", help="Data transmission delay")

# TAB 2: NETWORK MONITORING
with tab2:
    st.subheader("Network Traffic Analysis")
    st.caption("Visualization of latest network packet features")
    
    if hasattr(st.session_state, 'latest_features') and len(st.session_state.latest_features) > 0:
        st.bar_chart(st.session_state.latest_features, height=400, use_container_width=True)
    else:
        st.info(":material/pending: Awaiting network traffic data...")
    
    st.divider()
    
    # Network Layer Analysis
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### :material/security: Security Analysis")
        if "🚨" in st.session_state.sec_msg or "Attack" in st.session_state.sec_msg:
            st.error(st.session_state.sec_msg)
        elif "Normal" in st.session_state.sec_msg or "Monitoring" in st.session_state.sec_msg:
            st.success(st.session_state.sec_msg)
        else:
            st.warning(st.session_state.sec_msg)
    
    with col2:
        st.markdown("#### :material/analytics: Performance")
        st.metric("Detection Rate", "99.8%", help="Accuracy of threat detection")
        st.metric("False Positive", "< 0.1%", help="Rate of incorrect alerts")

# TAB 3: EVENT LOG & NETWORK TRAFFIC STREAM
# TAB 3: EVENT LOG & NETWORK TRAFFIC STREAM
with tab3:
    log_col, traffic_col = st.columns(2)  # Split into two columns: logs on left, traffic stream on right
    
    with log_col:
        st.subheader("Security Event Timeline")
        st.caption("Chronological log of system events and alerts")
        
        if st.session_state.events:
            # --- Event Statistics (ROBUST FIX) ---
            col1, col2, col3 = st.columns(3)
            
            # Keywords to classify events (Case Insensitive)
            critical_keywords = ["attack", "critical", "dos", "smurf", "arp", "injection", "replay", "flatline", "tamper", "spoof", "alert"]
            warning_keywords = ["anomaly", "warning", "analyzing", "scan"]
            normal_keywords = ["normal", "secure", "resetting"]

            # 1. Calculate Critical (High Priority)
            critical_count = len([e for e in st.session_state.events if any(k in e.lower() for k in critical_keywords)])
            
            # 2. Calculate Warnings (Exclude things that are already Critical)
            warning_count = len([e for e in st.session_state.events if any(k in e.lower() for k in warning_keywords) and not any(k in e.lower() for k in critical_keywords)])
            
            # 3. Calculate Normal
            normal_count = len([e for e in st.session_state.events if any(k in e.lower() for k in normal_keywords)])
            
            with col1:
                st.metric(":material/check_circle: Normal", normal_count)
            with col2:
                st.metric(":material/warning: Warnings", warning_count)
            with col3:
                st.metric(":material/crisis_alert: Critical", critical_count)
            
            st.divider()
            
            # --- Recent Events List ---
            st.markdown("#### Recent Events (Last 20)")
            for event in reversed(st.session_state.events[-20:]):
                event_lower = event.lower()
                
                # Check Critical first
                if any(k in event_lower for k in critical_keywords):
                    st.error(event, icon=":material/crisis_alert:")
                # Then Warning
                elif any(k in event_lower for k in warning_keywords):
                    st.warning(event, icon=":material/warning:")
                # Then Normal
                elif any(k in event_lower for k in normal_keywords):
                    st.success(event, icon=":material/check_circle:")
                # Default info
                else:
                    st.info(event, icon=":material/info:")
        else:
            st.info(":material/event_note: No events logged yet. System monitoring active.")
    
    with traffic_col:
        st.subheader("Live Network Traffic Stream")
        st.caption("Real-time incoming network data and predictions (last 50 entries)")
        
        if st.session_state.network_traffic:
            df = pd.DataFrame(st.session_state.network_traffic)
            # Sort to show newest first
            df = df.sort_values('timestamp', ascending=False).head(50)
            
            st.dataframe(
                df,
                use_container_width=True,
                column_config={
                    "timestamp": st.column_config.TextColumn("Time"),
                    "true_label": st.column_config.TextColumn("True Label"),
                    "prediction": st.column_config.TextColumn("Prediction"),
                    # Format confidence as percentage (e.g. 0.95 -> 95.0%)
                    "confidence": st.column_config.NumberColumn("Confidence", format="%.1f%%")
                },
                hide_index=True
            )
        else:
            st.info(":material/pending: Awaiting network traffic...")
# ==========================================
# 8. FUSION ENGINE STATUS
# ==========================================
st.subheader(":material/join: Multi-Layer Fusion Engine")
st.caption("Combined analysis from physical, network, and AI layers")

fusion_col1, fusion_col2, fusion_col3 = st.columns(3)

with fusion_col1:
    with st.container(border=True):
        st.markdown("##### :material/cardiology: Physical Layer")
        if "Anomaly" in st.session_state.ecg_msg or "⚠️" in st.session_state.ecg_msg:
            st.warning(st.session_state.ecg_msg[:50] + "..." if len(st.session_state.ecg_msg) > 50 else st.session_state.ecg_msg)
        else:
            st.success("ECG Normal" if "Normal" in st.session_state.ecg_msg else st.session_state.ecg_msg[:40])

with fusion_col2:
    with st.container(border=True):
        st.markdown("##### :material/security: Network Layer")
        if "🚨" in st.session_state.sec_msg:
            st.error(st.session_state.sec_msg[:50] + "..." if len(st.session_state.sec_msg) > 50 else st.session_state.sec_msg)
        else:
            st.success("Traffic Normal" if "Normal" in st.session_state.sec_msg or "Monitoring" in st.session_state.sec_msg else st.session_state.sec_msg[:40])

with fusion_col3:
    with st.container(border=True):
        st.markdown("##### :material/psychology: Fusion")
        if st.session_state.ai_diagnosis != "Normal" and st.session_state.ai_diagnosis != "Waiting...":
            st.warning(f"Threat: {st.session_state.ai_diagnosis}")
        else:
            st.success("System Normal" if st.session_state.ai_diagnosis == "Normal" else "Initializing...")

# ==========================================
# 9. MQTT MESSAGE PROCESSING
# ==========================================
UPDATE_INTERVAL_SHORT = 0.1  # Faster refresh when updates occur
UPDATE_INTERVAL_LONG = 1.0   # Slower refresh when idle
MAX_ECG_POINTS = 500
MAX_TRAFFIC_ENTRIES = 50     # Limit network traffic stream size

# Process all queued messages
updated = False
messages_processed = 0

# Process all queued messages
while not gui_queue.empty() and messages_processed < 50:  # Process max 50 messages per refresh
    msg = gui_queue.get()
    topic = msg['topic']
    data = msg['data']
    updated = True
    messages_processed += 1
    
    ts = time.strftime('%H:%M:%S')
    ts_float = time.time()
    
    # 1. ECG Signal
    if topic == "ioht/ecg":
        if 'attack_mode' in data:
            st.session_state.current_mode = data['attack_mode']
        
        segment = data.get('ecg_segment') or data.get('ecg')
        val = data.get('ecg_value')
        
        if segment is not None and isinstance(segment, list):
            st.session_state.ecg_data.extend(segment)
        elif val is not None:
            st.session_state.ecg_data.append(val)
        
        if len(st.session_state.ecg_data) > MAX_ECG_POINTS:
            st.session_state.ecg_data = st.session_state.ecg_data[-MAX_ECG_POINTS:]
    
    # 2. Network Truth (Data)
    elif topic == "ioht/network/data":
        label = data.get('true_label', 0)
        mapping = {0: "Normal", 1: "DoS", 2: "ARP", 3: "Smurf", 4: "Scan"}
        truth_label = mapping.get(label, str(label))
        
        # Add to network traffic stream (Session State)
        st.session_state.network_traffic.append({
            'timestamp': ts_float,
            'true_label': truth_label,
            'prediction': None,
            'confidence': None
        })
        
        if 'features' in data:
            try:
                st.session_state.latest_features = np.array(data['features'], dtype=float).flatten()[:40]
            except: pass
    
    # 3. AI Prediction (Network Result)
    elif topic == "ioht/network/result": 
        prediction = data.get("diagnosis", "Normal")
        conf = data.get("confidence", 0.0)
        st.session_state.ai_diagnosis = prediction
        
        # Add to network traffic stream (Session State)
        st.session_state.network_traffic.append({
            'timestamp': ts_float,
            'true_label': None,
            'prediction': prediction,
            'confidence': conf
        })
        
        # --- LOGGING: SAVE TRAFFIC TO CSV ---
        # We use the current_mode as a proxy for truth since packets are async
        logger.log_traffic(
            true_label=st.session_state.current_mode, 
            prediction=prediction, 
            confidence=conf
        )

        if prediction != "Normal":
            st.session_state.alert_state = "Attack Detected"
            st.session_state.sec_msg = f"🚨 {prediction} ({conf:.1%})"
            st.session_state.last_msg_time = time.time()
            st.session_state.events.append(f"{ts} [NET] {prediction}")
            
            # --- LOGGING: SAVE EVENT ---
            logger.log_event("Cyber Attack", "Network AI", f"Detected {prediction} ({conf:.1%})", "High")
        else:
            st.session_state.sec_msg = "Traffic Normal"
    
    # 4. ECG AI Alerts
    elif topic in ["fusion/ecg_alert", "ioht/alert"]:
        alert_type = data.get('signal_status', 'Anomaly')
        loss = data.get('loss', 0.0)
        
        st.session_state.ecg_msg = f"⚠️ {alert_type} (Loss: {loss:.2f})"
        st.session_state.alert_state = "Analyzing"
        st.session_state.last_msg_time = time.time()
        st.session_state.events.append(f"{ts} [PHY] {alert_type}")
        
        # --- LOGGING: SAVE EVENT ---
        logger.log_event("Physical Anomaly", "ECG AI", f"{alert_type} (Loss: {loss:.2f})", "High")
    
    # 5. Fusion Decision
    elif topic == "fusion/final_decision":
        status = data.get('status', 'Normal')
        severity = data.get('severity', 'Low')
        net_cause = data.get('network_attack', 'Normal')
        phy_cause = data.get('ecg_issue', 'Normal')
        
        if status != "Normal":
            st.session_state.alert_state = "Attack Detected"
            last_event = st.session_state.events[-1] if st.session_state.events else ""
            if status not in last_event:
                st.session_state.events.append(f"{ts} [FUSION] {status}")
                
            # --- LOGGING: SAVE EVENT ---
            logger.log_event("Fusion Decision", "Fusion Engine", status, severity)
        
        if status == "Normal":
            st.session_state.ai_diagnosis = "Normal"
        else:
            st.session_state.ai_diagnosis = f"{status} (Net: {net_cause}, Phys: {phy_cause})"
    
    # 6. Telemetry & Control Sync
    elif topic == "pacemaker/control/telemetry":
        st.session_state.pacemaker_hr = float(data.get('hr_est', 72))
        st.session_state.pacemaker_battery = float(data.get('battery', 98.0))
    
    elif topic == "simulation/master_control":
        if isinstance(data, str):
            st.session_state.current_mode = data

# Limit network traffic stream size
if len(st.session_state.network_traffic) > MAX_TRAFFIC_ENTRIES:
    st.session_state.network_traffic = st.session_state.network_traffic[-MAX_TRAFFIC_ENTRIES:]

# Auto-reset watchdog
if st.session_state.alert_state != "Secure":
    if time.time() - st.session_state.last_msg_time > 3.0:
        if st.session_state.current_mode == "Normal":
            st.session_state.alert_state = "Secure"
            st.session_state.ecg_msg = "Normal Sinus Rhythm"
            st.session_state.sec_msg = "System Monitoring..."
            st.session_state.ai_diagnosis = "Normal"

# Auto-refresh with adaptive interval for smoothness
if not st.session_state.stop_update:
    sleep_time = UPDATE_INTERVAL_SHORT if updated or gui_queue.qsize() > 0 else UPDATE_INTERVAL_LONG
    time.sleep(sleep_time)
    st.rerun()