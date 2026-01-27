@echo off
echo Starting IoHT Security Simulation (Hybrid Mode)...

:: Check if Mosquitto is already running
tasklist | findstr /i mosquitto >nul
if %errorlevel% equ 0 (
    echo MQTT Broker is already running. Skipping...
    goto :skip_mosquitto
)

:: 1. MQTT Broker (only start if not running)
start "1. MQTT Broker" cmd /k "mosquitto -v"
timeout /t 2 /nobreak >nul
:skip_mosquitto

:: 2. Simulators (Hardcoded Choice 3: Hybrid Mode)
echo Launching Physical Simulators...
start "2. Pacemaker ECG Simulator" cmd /k "python attacks_ecg_level\pacemaker_direct_sim.py"
start "3. ECG Attack Generator" cmd /k "python attacks_ecg_level\ecg_attack_generator.py"

echo Launching Network Traffic Simulator...
start "4. Network Attack Generator" cmd /k "python attacks_network_level\network_attack_generator.py"

:: 3. AI SERVICES
echo Launching AI Detection Services...
start "5. ECG AI Service" cmd /k "python ai_services\ecg_ai_service.py"
start "6. Network Security AI" cmd /k "python ai_services\network_security_ai.py"

timeout /t 2 /nobreak >nul

:: 4. Fusion
echo Launching Fusion Engine...
start "7. Fusion Service" cmd /k "python ai_services\fusion_service.py"

:: 5. Dashboard (FIXED: Added PYTHONPATH so it finds log_manager in logs folder)
echo Launching Dashboard...
start "8. Streamlit Dashboard" cmd /k "set PYTHONPATH=logs && python -m streamlit run dashboard\master_dashboard.py"

echo All systems initialized. Monitor the dashboard for status.