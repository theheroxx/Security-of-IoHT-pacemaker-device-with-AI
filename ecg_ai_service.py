import torch
import time
import json
import numpy as np
import paho.mqtt.client as mqtt
from collections import deque, Counter
import hashlib

# ================= CONFIG =================
MODEL_PATH = "models/ecg_bilstm_autoencoder.pth"
BROKER = "127.0.0.1"
PORT = 1883

TOPIC_INPUT = ["ioht/ecg", "pacemaker/direct_ecg_stream"]
TOPIC_ALERT = "fusion/ecg_alert"
TOPIC_STATUS = "ecg_ai/status"

SEQ_LEN = 140
TARGET_FS = 125

device = torch.device("cpu")
buffer = deque(maxlen=SEQ_LEN)

# ================= CALIBRATION =================
class SimpleCalibration:
    def __init__(self):
        self.is_calibrated = False
        self.loss_history = deque(maxlen=200)
        self.threshold = 0.08
        self.baseline_bpm = 75.0
        self.bpm_history = deque(maxlen=100)
        
    def add_data(self, loss, bpm=None):
        """اضافه کردن داده برای calibration"""
        if loss < 0.2:  # فیلتر noise
            self.loss_history.append(loss)
            if bpm and 40 < bpm < 180:
                self.bpm_history.append(bpm)
                
    def calibrate(self):
        """انجام calibration"""
        if len(self.loss_history) < 100:
            return False
            
        # محاسبه threshold
        loss_array = np.array(self.loss_history)
        mean_loss = np.mean(loss_array)
        std_loss = np.std(loss_array)
        
        # آستانه محکم: میانگین + 4*انحراف معیار
        self.threshold = mean_loss + (4 * std_loss)
        self.threshold = max(self.threshold, 0.08)  # حداقل
        
        # محاسبه baseline BPM
        if self.bpm_history:
            self.baseline_bpm = np.median(self.bpm_history)
            
        self.is_calibrated = True
        print(f"\n✅ CALIBRATION: Threshold={self.threshold:.4f}, BPM={self.baseline_bpm:.0f}")
        return True

calibration = SimpleCalibration()

# ================= MODEL =================
class ECG_Autoencoder(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = torch.nn.Conv1d(1, 32, 7, padding=3)
        self.pool = torch.nn.MaxPool1d(2)
        self.relu = torch.nn.ReLU()
        self.lstm_enc = torch.nn.LSTM(32, 64, batch_first=True, bidirectional=True)
        self.lstm_dec = torch.nn.LSTM(128, 64, batch_first=True, bidirectional=True)
        self.upsample = torch.nn.Upsample(scale_factor=2)
        self.conv2 = torch.nn.Conv1d(128, 1, 7, padding=3)

    def forward(self, x):
        x = x.permute(0, 2, 1)
        x = self.pool(self.relu(self.conv1(x)))
        x = x.permute(0, 2, 1)
        x, _ = self.lstm_enc(x)
        x, _ = self.lstm_dec(x)
        x = x.permute(0, 2, 1)
        x = self.conv2(self.upsample(x))
        return x.permute(0, 2, 1)

# بارگذاری مدل
try:
    model = ECG_Autoencoder()
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()
    print("🧠 ECG AI Model Loaded")
except Exception as e:
    print(f"❌ Model Error: {e}")
    exit(1)

# ================= SIGNAL PROCESSING =================
def normalize_signal(arr):
    """نرمال‌سازی ساده"""
    mean = np.mean(arr)
    std = np.std(arr)
    return (arr - mean) / std if std > 0.001 else arr - mean

def get_heart_rate(arr):
    """محاسبه ضربان قلب"""
    # ساده‌ترین روش: شمارش peaks
    peaks = []
    threshold = np.max(arr) * 0.6
    
    for i in range(2, len(arr)-2):
        if (arr[i] > threshold and 
            arr[i] > arr[i-1] and arr[i] > arr[i+1]):
            if not peaks or (i - peaks[-1]) > 30:  # refractory period
                peaks.append(i)
    
    if len(peaks) < 2:
        return None
        
    avg_interval = np.mean(np.diff(peaks))
    bpm = 60 / (avg_interval / TARGET_FS)
    return bpm

def check_signal_quality(arr):
    """بررسی کیفیت سیگنال"""
    # 1. Flatline
    amplitude = np.max(arr) - np.min(arr)
    if amplitude < 0.05:
        return "FLATLINE"
    
    # 2. Spike/Noise
    std_val = np.std(arr)
    if std_val > 5.0:
        return "NOISY"
    
    return "GOOD"

# ================= ANOMALY DETECTION =================
class AnomalyDetector:
    def __init__(self):
        self.alert_buffer = deque(maxlen=5)  # بافر برای تثبیت هشدار
        self.last_alert_time = 0
        self.min_alert_interval = 2.0
        
    def detect_anomaly(self, signal_array, ai_loss, threshold):
        """تشخیص اولیه آنومالی"""
        
        # 1. بررسی کیفیت سیگنال
        quality = check_signal_quality(signal_array)
        if quality != "GOOD":
            return quality, 0.95, {}
        
        # 2. تشخیص با AI (اولویت اصلی)
        if ai_loss > threshold:
            # محاسبه confidence بر اساس میزان آنومالی
            loss_ratio = ai_loss / threshold
            confidence = min(0.95, 0.5 + (loss_ratio - 1) * 0.2)
            
            # آنومالی تشخیص داده شد
            return "AI_ANOMALY", confidence, {"loss_ratio": loss_ratio}
        
        # 3. بررسی BPM (فقط اگر AI آنومالی ندید)
        bpm = get_heart_rate(signal_array)
        if bpm:
            # بررسی BPM غیرعادی
            if bpm > 160:
                return "HIGH_BPM", 0.8, {"bpm": bpm}
            elif bpm < 40:
                return "LOW_BPM", 0.8, {"bpm": bpm}
        
        # نرمال
        return "NORMAL", 0.0, {}
    
    def stabilize_alert(self, alert_type, confidence):
        """تثبیت هشدار برای جلوگیری از flicker"""
        current_time = time.time()
        
        # بررسی فاصله زمانی
        if current_time - self.last_alert_time < self.min_alert_interval:
            return None
            
        # اضافه کردن به بافر
        self.alert_buffer.append((alert_type, confidence))
        
        # بررسی consistency
        if len(self.alert_buffer) == self.alert_buffer.maxlen:
            types = [a[0] for a in self.alert_buffer]
            counts = Counter(types)
            most_common, count = counts.most_common(1)[0]
            
            # اگر 3 از 5 نمونه یکسان بودند
            if count >= 3 and most_common != "NORMAL":
                confidences = [a[1] for a in self.alert_buffer if a[0] == most_common]
                avg_confidence = np.mean(confidences) if confidences else 0
                
                if avg_confidence > 0.6:
                    self.last_alert_time = current_time
                    self.alert_buffer.clear()  # پاک کردن بعد از هشدار
                    return most_common, avg_confidence
        
        return None

detector = AnomalyDetector()

# ================= ANOMALY CLASSIFICATION =================
def classify_anomaly(anomaly_type, signal_array, details):
    """کلاس‌بندی آنومالی بعد از تشخیص"""
    
    if anomaly_type == "FLATLINE":
        return "Critical Signal Loss", {"reason": "flatline"}
    
    elif anomaly_type == "NOISY":
        return "Signal Interference", {"reason": "high_noise"}
    
    elif anomaly_type == "AI_ANOMALY":
        # بررسی نوع آنومالی AI
        loss_ratio = details.get("loss_ratio", 1.0)
        
        if loss_ratio > 2.0:
            return "Severe Physiological Anomaly", {"loss_ratio": loss_ratio}
        elif loss_ratio > 1.5:
            return "Moderate Anomaly", {"loss_ratio": loss_ratio}
        else:
            return "Mild Anomaly", {"loss_ratio": loss_ratio}
    
    elif anomaly_type == "HIGH_BPM":
        bpm = details.get("bpm", 0)
        return "Tachycardia", {"bpm": bpm}
    
    elif anomaly_type == "LOW_BPM":
        bpm = details.get("bpm", 0)
        return "Bradycardia", {"bpm": bpm}
    
    return "Normal", {}

# ================= REPLAY DETECTION =================
class SimpleReplayDetector:
    def __init__(self):
        self.history = deque(maxlen=50)  # تاریخچه محدود
        self.similarity_threshold = 0.95
        
    def check_replay(self, signal_array):
        """بررسی replay (ساده و محافظه‌کارانه)"""
        if len(signal_array) < 10:
            return False
            
        # نادیده گرفتن سیگنال‌های flat
        if np.std(signal_array) < 0.05:
            return False
            
        # ساخت signature
        normalized = normalize_signal(signal_array)
        signature = hashlib.md5(normalized.tobytes()).hexdigest()[:8]
        
        # بررسی در history
        if signature in self.history:
            return True
            
        # اضافه کردن به history
        self.history.append(signature)
        return False

replay_detector = SimpleReplayDetector()

# ================= MAIN PROCESSING =================
def process_window(client, signal_array):
    """پردازش یک پنجره سیگنال"""
    
    # نرمال‌سازی برای مدل
    normalized = normalize_signal(signal_array)
    
    # استنتاج مدل
    with torch.no_grad():
        x = torch.tensor(normalized, dtype=torch.float32).view(1, SEQ_LEN, 1)
        recon = model(x)
        loss = torch.mean(torch.abs(x - recon)).item()
    
    # CALIBRATION PHASE
    if not calibration.is_calibrated:
        bpm = get_heart_rate(normalized)
        calibration.add_data(loss, bpm)
        
        if calibration.calibrate():
            client.publish(TOPIC_STATUS, json.dumps({
                "timestamp": time.time(),
                "status": "calibrated",
                "threshold": calibration.threshold,
                "baseline_bpm": calibration.baseline_bpm
            }))
        
        print(f"\r🔧 Calibrating... {len(calibration.loss_history)}/100", end="")
        return
    
    # DETECTION PHASE
    # 1. تشخیص اولیه آنومالی
    anomaly_type, confidence, details = detector.detect_anomaly(
        signal_array, loss, calibration.threshold
    )
    
    # 2. بررسی replay (فقط اگر آنومالی داریم)
    if anomaly_type != "NORMAL" and replay_detector.check_replay(signal_array):
        anomaly_type = "REPLAY"
        confidence = 0.9
        details["replay_detected"] = True
    
    # 3. تثبیت هشدار
    stabilized = detector.stabilize_alert(anomaly_type, confidence)
    
    if stabilized:
        stable_type, stable_confidence = stabilized
        
        # 4. کلاس‌بندی آنومالی
        final_class, class_details = classify_anomaly(stable_type, signal_array, details)
        
        if final_class != "Normal":
            # ساخت پیام هشدار
            bpm = get_heart_rate(normalized)
            
            alert_payload = {
                "timestamp": time.time(),
                "signal_status": final_class,
                "loss": loss,
                "confidence": stable_confidence,
                "loss_threshold": calibration.threshold,
                "bpm_est": bpm,
                "details": class_details
            }
            
            # نمایش
            print(f"\n🚨 {final_class}")
            print(f"   Loss: {loss:.4f} (Threshold: {calibration.threshold:.4f})")
            print(f"   Confidence: {stable_confidence:.2f}")
            if bpm:
                print(f"   BPM: {bpm:.0f}")
            
            # ارسال
            client.publish(TOPIC_ALERT, json.dumps(alert_payload))
    
    else:
        # نمایش وضعیت نرمال
        print(f"\r💚 Normal | Loss: {loss:.4f} | Thresh: {calibration.threshold:.4f}", end="")

# ================= MQTT HANDLER =================
def on_message(client, userdata, msg):
    """پردازش پیام‌های MQTT"""
    try:
        payload = json.loads(msg.payload.decode())
        
        # استخراج segment
        segment = payload.get("ecg_segment") or payload.get("ecg") or []
        if not isinstance(segment, list):
            segment = [segment] if segment else []
        
        # پردازش samples
        for sample in segment:
            try:
                buffer.append(float(sample))
                
                # وقتی buffer پر شد پردازش کن
                if len(buffer) == SEQ_LEN:
                    process_window(client, np.array(buffer))
                    
            except (ValueError, TypeError):
                continue
                
    except Exception as e:
        print(f"Error: {e}")

# ================= MAIN =================
def main():
    print("="*60)
    print("🏥 ECG AI - Clean & Efficient")
    print("="*60)
    print("• First: Anomaly Detection")
    print("• Then: Classification")
    print("• Priority: AI Loss > BPM > Quality")
    print("="*60)
    
    # تنظیم MQTT
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, "ECG_AI_Clean")
    
    def on_connect(c, userdata, flags, reason_code, properties):
        print("✅ Connected to MQTT")
        c.subscribe([(topic, 0) for topic in TOPIC_INPUT])
    
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        client.connect(BROKER, PORT, 60)
        print("🔄 Starting...")
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
        client.disconnect()
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    main()