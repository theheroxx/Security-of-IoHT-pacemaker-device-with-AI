# sim_control.py
import time
import sys
import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion

BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "simulation/master_control"

client = mqtt.Client(
    client_id="sim_control",
    callback_api_version=CallbackAPIVersion.VERSION2
)

def set_mode(mode):
    client.publish(TOPIC, mode)
    print("Published mode:", mode)

@client.connect_callback()
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("Connected successfully")
        if mode_to_publish:
            set_mode(mode_to_publish)
            client.disconnect()  # Disconnect after publishing if it's a one-time action
    else:
        print(f"Connection failed with reason: {reason_code}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode_to_publish = sys.argv[1]
        client.connect(BROKER, PORT)
        client.loop_start()
        # Give time for connection and publish; adjust sleep if needed
        time.sleep(2)  # Wait for connection and publish to complete
        client.loop_stop()
    else:
        print("Usage: python sim_control.py <Mode>")
        print("Modes: Normal, DoS, ARP, Smurf, Scan, Injection, Replay, PacingCompromise")
        mode_to_publish = None