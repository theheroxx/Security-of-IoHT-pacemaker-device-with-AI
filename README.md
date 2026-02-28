# Security of IoHT Pacemaker Device with AI

This repository simulates hybrid cyber-physical attacks on an IoHT pacemaker workflow and uses AI services plus a Streamlit dashboard for detection and monitoring.

## Current runtime components

- `attacks_ecg_level/pacemaker_direct_sim.py` (ECG generator + physical attack modes)
- `attacks_network_level/network_attack_generator.py` (network packet simulator)
- `ai_services/ecg_ai_service.py` (ECG anomaly detector)
- `ai_services/network_security_ai.py` (network attack classifier)
- `ai_services/fusion_service.py` (decision fusion engine)
- `dashboard/master_dashboard.py` (frontend)


<img width="1408" height="768" alt="530489177-a96a5836-03fe-499f-9f71-397946b9bbe4" src="https://github.com/user-attachments/assets/af59e855-c514-427b-8d7a-1916412c228c" />


## Dockerized orchestration (new)

A Docker Compose setup has been added under `infra/docker/docker-compose.yml`.

### Quick start
This project is dockerized, but for a fast test you can execute:
run_simulation.bat

```bash
cp .env.example .env
make up
```

Open dashboard at:

- http://localhost:8501

### Stop

```bash
make down
```

## Environment variables

Services support:

- `MQTT_BROKER_HOST` (default `127.0.0.1`)
- `MQTT_BROKER_PORT` (default `1883`)
- `LOG_DIR` (default `logs`, used by `logs/log_manager.py`)
