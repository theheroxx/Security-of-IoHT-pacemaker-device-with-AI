@echo off
echo Starting IoHT Security Simulation...

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

:: Prompt user for simulator choice
echo Choose simulator mode:
echo 1. Direct Pacemaker Attacks Only
echo 2. Network Attacks Only
echo 3. Both (Hybrid - Risk of Topic Conflict Unless Fixed)
set /p choice=Enter choice (1/2/3): 

:: 2. Controllers
start "2. Simulation Controller" cmd /k "python sim_control.py"
timeout /t 1 /nobreak >nul

:: 3. ECG & Network Simulators (conditional)
if %choice%==1 (
    start "3. Pacemaker ECG Simulator" cmd /k "python pacemaker_direct_sim.py"
) else if %choice%==2 (
    start "4. ECG Attack Generator" cmd /k "python ecg_attack_generator.py"
) else if %choice%==3 (
    start "3. Pacemaker ECG Simulator" cmd /k "python pacemaker_direct_sim.py"
    start "4. ECG Attack Generator" cmd /k "python ecg_attack_generator.py"
) else (
    echo Invalid choice. Starting both by default.
    start "3. Pacemaker ECG Simulator" cmd /k "python pacemaker_direct_sim.py"
    start "4. ECG Attack Generator" cmd /k "python ecg_attack_generator.py"
)
start "5. Network Attack Generator" cmd /k "python network_attack_generator.py"

:: 4. AI SERVICES (important: before fusion)
start "6. ECG AI Service" cmd /k "python ecg_ai_service.py"
start "7. Network Security AI" cmd /k "python network_security_ai.py"
timeout /t 2 /nobreak >nul

:: 5. Fusion
start "8. Fusion Service" cmd /k "python fusion_service.py"

:: 6. Dashboard
start "9. Streamlit Dashboard" cmd /k "python -m streamlit run master_dashboard.py"

echo All systems initialized.