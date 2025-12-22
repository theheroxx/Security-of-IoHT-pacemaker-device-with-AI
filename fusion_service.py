import json
import time
import paho.mqtt.client as mqtt
import numpy as np
from collections import deque
from datetime import datetime
import hashlib

# ==========================================
# CONFIGURATION
# ==========================================
BROKER = "127.0.0.1"
PORT = 1883

# Inputs (Must match AI outputs)
TOPIC_ECG_ALERT = "fusion/ecg_alert"
TOPIC_NET_ALERT = "fusion/network_alert"
TOPIC_ECG_RAW = "pacemaker/direct_ecg_stream"  # For direct monitoring
TOPIC_NET_RAW = "ioht/network/data"           # For raw network data

# Outputs (Must match Dashboard inputs)
TOPIC_FINAL_DECISION = "fusion/final_decision"
TOPIC_SYSTEM_STATUS = "fusion/system_status"
TOPIC_ATTACK_RESPONSE = "fusion/attack_response"
TOPIC_VISUALIZATION = "fusion/visualization_data"

# Tuning Parameters
FUSION_WINDOW = 2.0         # Events within 2s are correlated
CORRELATION_WINDOW = 7.0    # Keep history for analysis
MIN_PUBLISH_INTERVAL = 0.3  # Prevent spamming
CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence for alerts
DECAY_RATE = 0.1            # Confidence decay per second

# Risk Mapping
SEVERITY_MAP = {
    # Physical - Critical
    "Critical Signal Loss": "CRITICAL",
    "Flatline": "CRITICAL",
    "Voltage Injection": "CRITICAL",
    "Spike Injection": "CRITICAL",
    "Pacing Compromise": "CRITICAL",
    
    # Physical - High
    "Rate Tampering": "HIGH",
    "Bradycardia": "HIGH",
    "Tachycardia": "HIGH",
    "Asystole": "HIGH",
    
    # Physical - Medium
    "Morphology Anomaly": "MEDIUM",
    "Signal Interference": "MEDIUM",
    "Noise Artifact": "MEDIUM",
    "Arrhythmia": "MEDIUM",
    
    # Network - Critical
    "ARP Spoofing": "CRITICAL",
    "Man-in-the-Middle": "CRITICAL",
    "Command Injection": "CRITICAL",
    
    # Network - High
    "DoS Attack": "HIGH",
    "Smurf Attack": "HIGH",
    "DDoS": "HIGH",
    "Flooding": "HIGH",
    
    # Network - Medium
    "Port Scan": "MEDIUM",
    "Reconnaissance": "MEDIUM",
    "Packet Injection": "MEDIUM",
    
    # Network - Low
    "Suspicious Activity": "LOW",
    "Anomalous Traffic": "LOW",
    
    # Default
    "Normal": "LOW",
    "Unknown": "LOW"
}

# ==========================================
# ADVANCED FUSION STATE
# ==========================================
class AdvancedFusionState:
    def __init__(self):
        # Event buffers with timestamps
        self.ecg_events = deque(maxlen=100)
        self.network_events = deque(maxlen=100)
        
        # Active events with confidence scores
        self.active_ecg = None
        self.active_network = None
        self.ecg_confidence = 0.0
        self.net_confidence = 0.0
        
        # Timing
        self.last_ecg_time = 0
        self.last_net_time = 0
        self.last_decision_time = 0
        self.last_decision_hash = ""
        
        # Attack correlation matrix (network → physical)
        self.correlation_matrix = {
            "DoS Attack": ["Critical Signal Loss", "Signal Interference"],
            "Smurf Attack": ["Critical Signal Loss", "Rate Tampering"],
            "ARP Spoofing": ["Rate Tampering", "Voltage Injection", "Spike Injection"],
            "Port Scan": ["Morphology Anomaly"],
            "Man-in-the-Middle": ["Voltage Injection", "Spike Injection", "Pacing Compromise"],
            "Packet Injection": ["Spike Injection", "Morphology Anomaly"]
        }
        
        # System state
        self.risk_level = "NORMAL"
        self.risk_history = deque(maxlen=50)
        self.attack_timeline = deque(maxlen=20)
        
        # Device context
        self.device_context = {}
        self.patient_state = {
            "baseline_hr": 72,
            "hr_variability": 0.1,
            "last_normal_time": time.time()
        }
        
        # Performance metrics
        self.metrics = {
            "total_alerts": 0,
            "false_positives": 0,
            "true_positives": 0,
            "fusion_count": 0,
            "avg_decision_time": 0
        }

state = AdvancedFusionState()

# ==========================================
# INTELLIGENT SCENARIO DETECTION
# ==========================================
SCENARIO_DATABASE = {
    "SCENARIO_1": {
        "id": "TARGETED_PACING_ATTACK",
        "name": "Targeted Pacing Attack",
        "description": "MITM (ARP Spoofing) followed by pacing command injection",
        "indicators": {
            "network": ["ARP Spoofing", "Man-in-the-Middle"],
            "ecg": ["Voltage Injection", "Spike Injection", "Rate Tampering", "Pacing Compromise"],
            "temporal_pattern": "network_first",  # Network attack precedes physical
            "confidence_boost": 0.35,
            "response": "EMERGENCY_ISOLATION",
            "medical_risk": "LIFE_THREATENING"
        }
    },
    "SCENARIO_2": {
        "id": "NETWORK_INDUCED_DOS",
        "name": "Network-Induced Denial of Service",
        "description": "DDoS attack causing ECG signal loss and monitoring disruption",
        "indicators": {
            "network": ["DoS Attack", "Smurf Attack", "DDoS", "Flooding"],
            "ecg": ["Critical Signal Loss", "Flatline", "Signal Interference"],
            "temporal_pattern": "simultaneous",
            "confidence_boost": 0.25,
            "response": "BANDWIDTH_PRIORITIZATION",
            "medical_risk": "HIGH"
        }
    },
    "SCENARIO_3": {
        "id": "STEALTHY_RECON_EXFIL",
        "name": "Stealthy Reconnaissance & Exfiltration",
        "description": "Port scanning followed by subtle data manipulation",
        "indicators": {
            "network": ["Port Scan", "Reconnaissance"],
            "ecg": ["Morphology Anomaly", "Arrhythmia"],
            "temporal_pattern": "ecg_first",  # Physical anomalies may appear first
            "confidence_boost": 0.15,
            "response": "ENHANCED_MONITORING",
            "medical_risk": "MEDIUM"
        }
    },
    "SCENARIO_4": {
        "id": "REPLAY_ATTACK",
        "name": "Replay Attack with Data Manipulation",
        "description": "Old data replay combined with command injection",
        "indicators": {
            "network": ["Packet Injection", "Replay"],
            "ecg": ["Morphology Anomaly", "Rate Tampering"],
            "temporal_pattern": "simultaneous",
            "confidence_boost": 0.20,
            "response": "SESSION_RESET",
            "medical_risk": "HIGH"
        }
    }
}

# ==========================================
# ADVANCED FUSION ALGORITHMS
# ==========================================
def calculate_temporal_correlation(ecg_time, net_time):
    """Calculate correlation based on timing patterns"""
    time_diff = abs(ecg_time - net_time)
    
    if time_diff < 0.5:  # Within 500ms
        return 0.9  # Strong correlation
    elif time_diff < 2.0:  # Within 2 seconds
        return 0.7  # Moderate correlation
    elif time_diff < 5.0:  # Within 5 seconds
        return 0.4  # Weak correlation
    else:
        return 0.1  # Very weak correlation

def match_attack_scenario(ecg_event, net_event):
    """Intelligent scenario matching with confidence scoring"""
    if not ecg_event and not net_event:
        return None
    
    best_match = None
    highest_score = 0.0
    
    ecg_type = ecg_event.get('signal_status', 'Normal') if ecg_event else 'Normal'
    net_type = net_event.get('attack_class', 'Normal') if net_event else 'Normal'
    ecg_time = ecg_event.get('timestamp', 0) if ecg_event else 0
    net_time = net_event.get('timestamp', 0) if net_event else 0
    
    for scenario_id, scenario in SCENARIO_DATABASE.items():
        score = 0.0
        
        # Network indicator matching
        if net_type in scenario['indicators']['network']:
            score += 0.4
        
        # ECG indicator matching (partial string matching)
        for ecg_indicator in scenario['indicators']['ecg']:
            if ecg_indicator in ecg_type:
                score += 0.4
                break
        
        # Temporal pattern matching
        temporal_pattern = scenario['indicators']['temporal_pattern']
        if temporal_pattern == "network_first" and net_time < ecg_time and net_time > 0:
            score += 0.1
        elif temporal_pattern == "ecg_first" and ecg_time < net_time and ecg_time > 0:
            score += 0.1
        elif temporal_pattern == "simultaneous" and abs(ecg_time - net_time) < 1.0:
            score += 0.1
        
        # Apply confidence boost
        score += scenario['indicators']['confidence_boost']
        
        # Cap at 1.0
        score = min(score, 1.0)
        
        if score > highest_score and score > 0.5:  # Minimum threshold
            highest_score = score
            best_match = {
                'scenario_id': scenario_id,
                'name': scenario['name'],
                'description': scenario['description'],
                'confidence': score,
                'response': scenario['indicators']['response'],
                'medical_risk': scenario['indicators']['medical_risk']
            }
    
    return best_match

def calculate_risk_score(ecg_event, net_event, scenario=None):
    """Calculate comprehensive risk score"""
    base_score = 0.0
    
    # Base score from ECG severity
    if ecg_event:
        ecg_severity = ecg_event.get('signal_status', 'Normal')
        severity_level = SEVERITY_MAP.get(ecg_severity, 'LOW')
        if severity_level == 'CRITICAL':
            base_score += 0.8
        elif severity_level == 'HIGH':
            base_score += 0.6
        elif severity_level == 'MEDIUM':
            base_score += 0.4
    
    # Base score from network severity
    if net_event:
        net_severity = net_event.get('attack_class', 'Normal')
        severity_level = SEVERITY_MAP.get(net_severity, 'LOW')
        if severity_level == 'CRITICAL':
            base_score += 0.7
        elif severity_level == 'HIGH':
            base_score += 0.5
        elif severity_level == 'MEDIUM':
            base_score += 0.3
    
    # Correlation boost
    if ecg_event and net_event:
        temporal_corr = calculate_temporal_correlation(
            ecg_event.get('timestamp', 0),
            net_event.get('timestamp', 0)
        )
        base_score += temporal_corr * 0.3
    
    # Scenario boost
    if scenario:
        base_score += scenario['confidence'] * 0.4
    
    # Normalize to 0-1
    risk_score = min(max(base_score, 0.0), 1.0)
    
    # Convert to risk level
    if risk_score > 0.8:
        return "CRITICAL", risk_score
    elif risk_score > 0.6:
        return "HIGH", risk_score
    elif risk_score > 0.4:
        return "MEDIUM", risk_score
    elif risk_score > 0.2:
        return "LOW", risk_score
    else:
        return "NORMAL", risk_score

# ==========================================
# ENHANCED FUSION ENGINE
# ==========================================
def perform_advanced_fusion():
    """Main fusion algorithm with intelligent decision making"""
    now = time.time()
    
    # 1. Prune old events and decay confidence
    if state.active_ecg and (now - state.last_ecg_time > FUSION_WINDOW):
        state.ecg_confidence -= DECAY_RATE * (now - state.last_ecg_time)
        if state.ecg_confidence < 0.1:
            state.active_ecg = None
    
    if state.active_network and (now - state.last_net_time > FUSION_WINDOW):
        state.net_confidence -= DECAY_RATE * (now - state.last_net_time)
        if state.net_confidence < 0.1:
            state.active_network = None
    
    # 2. Get current events
    current_ecg = state.active_ecg if state.ecg_confidence > 0.3 else None
    current_net = state.active_network if state.net_confidence > 0.3 else None
    
    # 3. Scenario detection
    detected_scenario = match_attack_scenario(current_ecg, current_net)
    
    # 4. Risk assessment
    risk_level, risk_score = calculate_risk_score(current_ecg, current_net, detected_scenario)
    
    # 5. Update system state
    state.risk_level = risk_level
    state.risk_history.append({
        "timestamp": now,
        "level": risk_level,
        "score": risk_score,
        "scenario": detected_scenario['name'] if detected_scenario else None
    })
    
    # 6. Build comprehensive decision
    decision = {
        "timestamp": now,
        "iso_timestamp": datetime.fromtimestamp(now).isoformat(),
        "decision_id": hashlib.md5(f"{now}{risk_score}".encode()).hexdigest()[:8],
        "risk_level": risk_level,
        "risk_score": round(risk_score, 3),
        "fusion_type": determine_fusion_type(current_ecg, current_net),
        "confidence": calculate_overall_confidence(current_ecg, current_net)
    }
    
    # Add ECG details
    if current_ecg:
        decision.update({
            "ecg_anomaly": current_ecg.get("signal_status"),
            "ecg_loss": current_ecg.get("loss"),
            "ecg_confidence": round(state.ecg_confidence, 3),
            "ecg_timestamp": current_ecg.get("timestamp")
        })
    
    # Add Network details
    if current_net:
        decision.update({
            "network_attack": current_net.get("attack_class"),
            "network_confidence": current_net.get("confidence"),
            "network_timestamp": current_net.get("timestamp")
        })
    
    # Add scenario information
    if detected_scenario:
        decision.update({
            "detected_scenario": detected_scenario["name"],
            "scenario_confidence": round(detected_scenario["confidence"], 3),
            "recommended_response": detected_scenario["response"],
            "medical_risk": detected_scenario["medical_risk"],
            "scenario_description": detected_scenario["description"]
        })
    
    # Add system context
    decision.update({
        "active_events": {
            "ecg": bool(current_ecg),
            "network": bool(current_net)
        },
        "time_since_last_normal": round(now - state.patient_state["last_normal_time"], 1),
        "risk_trend": calculate_risk_trend()
    })
    
    # Update metrics
    state.metrics["fusion_count"] += 1
    if risk_level != "NORMAL":
        state.metrics["total_alerts"] += 1
    
    return decision

def determine_fusion_type(ecg_event, net_event):
    """Determine the type of fusion occurring"""
    if ecg_event and net_event:
        # Check correlation matrix
        net_type = net_event.get('attack_class', '')
        ecg_type = ecg_event.get('signal_status', '')
        
        if net_type in state.correlation_matrix:
            if any(indicator in ecg_type for indicator in state.correlation_matrix[net_type]):
                return "STRONG_CYBER_PHYSICAL_CORRELATION"
        
        temporal_corr = calculate_temporal_correlation(
            ecg_event.get('timestamp', 0),
            net_event.get('timestamp', 0)
        )
        
        if temporal_corr > 0.7:
            return "HIGHLY_CORRELATED_EVENTS"
        elif temporal_corr > 0.4:
            return "MODERATELY_CORRELATED_EVENTS"
        else:
            return "COINCIDENTAL_EVENTS"
    
    elif ecg_event:
        return "PURE_PHYSICAL_ANOMALY"
    
    elif net_event:
        return "PURE_CYBER_ATTACK"
    
    return "NO_EVENTS"

def calculate_overall_confidence(ecg_event, net_event):
    """Calculate overall confidence for the decision"""
    confidence = 0.5  # Base confidence
    
    if ecg_event:
        confidence += 0.2 * state.ecg_confidence
    
    if net_event:
        net_conf = net_event.get('confidence', 0.5)
        confidence += 0.2 * min(net_conf, 1.0)
    
    if ecg_event and net_event:
        temporal_corr = calculate_temporal_correlation(
            ecg_event.get('timestamp', 0),
            net_event.get('timestamp', 0)
        )
        confidence += 0.1 * temporal_corr
    
    return min(max(confidence, 0.0), 1.0)

def calculate_risk_trend():
    """Calculate trend of risk over time"""
    if len(state.risk_history) < 3:
        return "STABLE"
    
    recent = list(state.risk_history)[-5:]
    risk_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NORMAL": 0}
    
    numeric_levels = [risk_map.get(item["level"], 0) for item in recent]
    if len(numeric_levels) >= 2:
        if numeric_levels[-1] > numeric_levels[0] + 1:
            return "RAPIDLY_INCREASING"
        elif numeric_levels[-1] > numeric_levels[0]:
            return "INCREASING"
        elif numeric_levels[-1] < numeric_levels[0]:
            return "DECREASING"
    
    return "STABLE"

# ==========================================
# ENHANCED MQTT HANDLERS
# ==========================================
def handle_ecg_alert(client, userdata, msg):
    """Enhanced ECG alert handler"""
    try:
        payload = json.loads(msg.payload.decode())
        
        # Create enriched event
        event = {
            "signal_status": payload.get("signal_status", "Unknown"),
            "loss": payload.get("loss"),
            "device_id": payload.get("device_id", "unknown"),
            "attack_hint": payload.get("attack_mode_hint", ""),
            "bpm": payload.get("bpm_est"),
            "timestamp": time.time(),
            "confidence": 1.0  # ECG alerts are usually high confidence
        }
        
        # Store event
        state.ecg_events.append(event)
        state.active_ecg = event
        state.ecg_confidence = 1.0
        state.last_ecg_time = time.time()
        
        # Log for debugging
        if event["signal_status"] != "Normal":
            print(f"💓 ECG Alert: {event['signal_status']} | Loss: {event.get('loss', 0):.4f}")
        
        # Trigger fusion
        trigger_enhanced_fusion(client)
        
    except Exception as e:
        print(f"❌ ECG Handler Error: {e}")

def handle_network_alert(client, userdata, msg):
    """Enhanced network alert handler"""
    try:
        payload = json.loads(msg.payload.decode())
        
        # Check confidence threshold
        confidence = payload.get("confidence", 0.5)
        if confidence < CONFIDENCE_THRESHOLD:
            return
        
        # Create enriched event
        event = {
            "attack_class": payload.get("predicted_class", "Unknown"),
            "confidence": confidence,
            "src": payload.get("src", "unknown"),
            "features": payload.get("features", []),
            "timestamp": time.time()
        }
        
        # Store event
        state.network_events.append(event)
        state.active_network = event
        state.net_confidence = confidence
        state.last_net_time = time.time()
        
        # Log for debugging
        if event["attack_class"] != "Normal":
            print(f"🌐 Network Alert: {event['attack_class']} | Conf: {confidence:.2f}")
        
        # Trigger fusion
        trigger_enhanced_fusion(client)
        
    except Exception as e:
        print(f"❌ Network Handler Error: {e}")

# ==========================================
# INTELLIGENT FUSION TRIGGER
# ==========================================
def trigger_enhanced_fusion(client):
    """Enhanced fusion trigger with anti-spam and context awareness"""
    now = time.time()
    
    # Check minimum interval
    if now - state.last_decision_time < MIN_PUBLISH_INTERVAL:
        return
    
    # Perform fusion
    decision = perform_advanced_fusion()
    
    # Create decision hash for deduplication
    decision_str = json.dumps(decision, sort_keys=True)
    decision_hash = hashlib.md5(decision_str.encode()).hexdigest()
    
    # Avoid publishing identical decisions
    if decision_hash == state.last_decision_hash:
        return
    
    state.last_decision_hash = decision_hash
    state.last_decision_time = now
    
    # Publish decision
    publish_enhanced_decision(client, decision)
    
    # Publish system status
    publish_system_status(client)
    
    # Generate response if needed
    if decision["risk_level"] in ["HIGH", "CRITICAL"]:
        generate_automated_response(client, decision)

# ==========================================
# PUBLISHING FUNCTIONS
# ==========================================
def publish_enhanced_decision(client, decision):
    """Publish enhanced decision with rich information"""
    # Console output
    print("\n" + "="*70)
    print("🛡️  ADVANCED FUSION ENGINE - DECISION")
    print("="*70)
    
    # Color-coded risk level
    risk_colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠", 
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "NORMAL": "🟢"
    }
    
    color = risk_colors.get(decision["risk_level"], "⚪")
    print(f"{color} RISK LEVEL: {decision['risk_level']} (Score: {decision['risk_score']:.2f})")
    
    if "detected_scenario" in decision:
        print(f"🎯 DETECTED SCENARIO: {decision['detected_scenario']}")
        print(f"   Description: {decision['scenario_description']}")
        print(f"   Confidence: {decision['scenario_confidence']:.1%}")
        print(f"   Medical Risk: {decision['medical_risk']}")
        print(f"   Recommended: {decision['recommended_response']}")
    
    if "ecg_anomaly" in decision and decision["ecg_anomaly"] != "Normal":
        print(f"💓 ECG ANOMALY: {decision['ecg_anomaly']} (Conf: {decision.get('ecg_confidence', 1.0):.2f})")
    
    if "network_attack" in decision and decision["network_attack"] != "Normal":
        print(f"🌐 NETWORK ATTACK: {decision['network_attack']} (Conf: {decision.get('network_confidence', 0.5):.2f})")
    
    print(f"🧠 Fusion Type: {decision['fusion_type']}")
    print(f"📊 Overall Confidence: {decision.get('confidence', 0.5):.2f}")
    print(f"📈 Risk Trend: {decision.get('risk_trend', 'STABLE')}")
    print("="*70 + "\n")
    
    # Publish to MQTT
    client.publish(TOPIC_FINAL_DECISION, json.dumps(decision, indent=2))

def publish_system_status(client):
    """Publish system status for dashboard"""
    status = {
        "timestamp": time.time(),
        "system_risk": state.risk_level,
        "active_ecg": bool(state.active_ecg),
        "active_network": bool(state.active_network),
        "ecg_confidence": round(state.ecg_confidence, 2),
        "net_confidence": round(state.net_confidence, 2),
        "fusion_count": state.metrics["fusion_count"],
        "risk_trend": calculate_risk_trend()
    }
    
    client.publish(TOPIC_SYSTEM_STATUS, json.dumps(status))

def generate_automated_response(client, decision):
    """Generate automated response based on decision"""
    response = {
        "timestamp": time.time(),
        "trigger_decision": decision["risk_level"],
        "trigger_scenario": decision.get("detected_scenario", "Unknown"),
        "actions": [],
        "priority": "HIGH" if decision["risk_level"] == "CRITICAL" else "MEDIUM"
    }
    
    # Define response actions based on risk level and scenario
    if decision["risk_level"] == "CRITICAL":
        response["actions"] = [
            "IMMEDIATE_DEVICE_ISOLATION",
            "ACTIVATE_EMERGENCY_PROTOCOL",
            "NOTIFY_CLINICAL_STAFF",
            "ENABLE_FALLBACK_MONITORING",
            "INITIATE_FORENSIC_LOGGING"
        ]
    elif decision["risk_level"] == "HIGH":
        response["actions"] = [
            "THROTTLE_NETWORK_TRAFFIC",
            "ENHANCE_AUTHENTICATION",
            "INCREASE_LOGGING_VERBOSITY",
            "ALERT_SECURITY_TEAM",
            "VALIDATE_DEVICE_CERTIFICATES"
        ]
    
    # Add scenario-specific actions
    if "recommended_response" in decision:
        response["actions"].append(decision["recommended_response"])
    
    # Publish response
    if response["actions"]:
        print(f"🚀 Executing Automated Response: {response['actions']}")
        client.publish(TOPIC_ATTACK_RESPONSE, json.dumps(response))

# ==========================================
# MAIN SETUP
# ==========================================
def on_connect(client, userdata, flags, reason_code, properties=None):
    print("✅ Advanced Fusion Engine Connected to MQTT Broker")
    
    # Subscribe to all required topics
    client.subscribe(TOPIC_ECG_ALERT)
    client.subscribe(TOPIC_NET_ALERT)
    
    # Optional: Subscribe to raw data for monitoring
    client.subscribe(TOPIC_ECG_RAW)
    client.subscribe(TOPIC_NET_RAW)
    
    # Publish initial status
    publish_system_status(client)

def main():
    """Main function"""
    print("="*70)
    print("🏥 ADVANCED CYBER-PHYSICAL FUSION ENGINE v2.0")
    print("="*70)
    print(f"• Broker: {BROKER}:{PORT}")
    print(f"• Fusion Window: {FUSION_WINDOW}s")
    print(f"• Confidence Threshold: {CONFIDENCE_THRESHOLD}")
    print(f"• Scenarios Loaded: {len(SCENARIO_DATABASE)}")
    print("="*70)
    
    # Setup MQTT client
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, 
                        client_id="Advanced_Fusion_Engine_v2")
    
    # Configure callbacks
    client.on_connect = on_connect
    client.message_callback_add(TOPIC_ECG_ALERT, handle_ecg_alert)
    client.message_callback_add(TOPIC_NET_ALERT, handle_network_alert)
    
    # Connect and start
    try:
        client.connect(BROKER, PORT, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n👋 Fusion Engine Shutting Down...")
        client.disconnect()
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    main()