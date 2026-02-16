import csv
import os
from datetime import datetime

class LogManager:
    def __init__(self):
        self.log_dir = os.getenv('LOG_DIR', 'logs')

        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # 1. Event Log File (Alerts, Diagnosis)
        self.event_file = os.path.join(self.log_dir, f"events_{datetime.now().strftime('%Y%m%d')}.csv")
        self._init_csv(self.event_file, ["Timestamp", "Type", "Source", "Message", "Severity"])

        # 2. Network Traffic File (Packet Stream)
        self.traffic_file = os.path.join(self.log_dir, f"network_traffic_{datetime.now().strftime('%Y%m%d')}.csv")
        self._init_csv(self.traffic_file, ["Timestamp", "True_Label", "AI_Prediction", "Confidence"])

    def _init_csv(self, filepath, headers):
        """Creates the file with headers if it doesn't exist."""
        if not os.path.exists(filepath):
            with open(filepath, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def log_event(self, type, source, message, severity="Info"):
        """Logs a system event (e.g., 'Attack Detected')."""
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.event_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([ts, type, source, message, severity])

    def log_traffic(self, true_label, prediction, confidence):
        """Logs a network packet classification result."""
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.traffic_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([ts, true_label, prediction, f"{confidence:.4f}"])

# Create a global instance
logger = LogManager()