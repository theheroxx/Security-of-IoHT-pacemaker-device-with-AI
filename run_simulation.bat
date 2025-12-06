@echo off
echo Starting IoHT Security Simulation...

:: 1. Start MQTT Broker
start "1. MQTT Broker" cmd /k "mosquitto -v"
timeout /t 2 /nobreak >nul

:: 2. Start Simulators
start "2. Pacemaker Device" cmd /k "python pacemaker_device.py"
start "3. Traffic Simulator" cmd /k "python network_traffic_sim.py"

:: 3. Start AI Services
start "4. ECG AI Service" cmd /k "python ecg_ai_service.py"
start "5. Network Security AI" cmd /k "python network_security_ai.py"

:: 4. Start Dashboard
start "6. Streamlit Dashboard" cmd /k "python -m streamlit run master_dashboard.py"

echo All systems initialized.