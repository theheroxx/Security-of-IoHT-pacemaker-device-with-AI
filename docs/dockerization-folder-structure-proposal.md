# Repository Foldering Review & Dockerization-Oriented Restructure Proposal

## 1) Current Layout (Observed)

The repository currently mixes runtime services, simulation generators, model artifacts, notebooks, logs, and datasets at the same top-level depth:

- `ai_services/` – model inference and fusion runtime services.
- `dashboard/` – Streamlit UI.
- `attacks_ecg_level/` + `attacks_network_level/` – simulation/attack generators.
- `logs/` – runtime log code + generated CSV logs.
- `models/` and `data/` – model binaries and datasets.
- `train/` – notebooks for experimentation/training.
- `node-red/` – external flow assets.

A Windows `.bat` script orchestrates all processes locally and relies on relative paths and environment assumptions.

## 2) Main Issues for Containerization

1. **No clear app boundary per deployable unit** (dashboard, ECG AI, network AI, fusion, simulators are all script-level entrypoints).
2. **Source and generated artifacts are mixed** (`logs/` contains both code and runtime CSV output).
3. **Training + production concerns are mixed** (`train/` notebooks + production services in one flat namespace).
4. **No environment-specific manifests per component** (single `requirements.txt` for everything).
5. **OS-specific orchestration** (`run_simulation.bat`) limits portability.

## 3) Suggested Standard Structure (Backend/Frontend + Infra)

```text
.
├─ apps/
│  ├─ frontend/
│  │  └─ dashboard/                  # Streamlit app (UI)
│  │     ├─ src/
│  │     ├─ requirements.txt
│  │     └─ Dockerfile
│  ├─ backend/
│  │  ├─ ecg-service/                # from ai_services/ecg_ai_service.py
│  │  │  ├─ src/
│  │  │  ├─ requirements.txt
│  │  │  └─ Dockerfile
│  │  ├─ network-security-service/   # from ai_services/network_security_ai.py
│  │  ├─ fusion-service/             # from ai_services/fusion_service.py
│  │  └─ simulator/
│  │     ├─ ecg-sim/                 # from attacks_ecg_level/*
│  │     └─ network-sim/             # from attacks_network_level/*
│  └─ shared/
│     └─ ioht_common/                # common MQTT topics, schemas, logging helpers
│
├─ models/                           # versioned model artifacts only
├─ datasets/                         # optional local dev datasets (gitignored if large)
├─ training/
│  ├─ notebooks/
│  └─ pipelines/
│
├─ infra/
│  ├─ docker/
│  │  ├─ docker-compose.yml
│  │  ├─ mosquitto/
│  │  │  └─ mosquitto.conf
│  │  └─ node-red/
│  └─ scripts/
│     ├─ dev-up.sh
│     └─ dev-down.sh
│
├─ storage/
│  ├─ logs/                          # runtime bind volume target
│  └─ exports/
│
├─ tests/
│  ├─ unit/
│  └─ integration/
└─ docs/
```

## 4) Backend vs Frontend Split (Practical)

- **Frontend container**: Streamlit dashboard only.
- **Backend containers**:
  - ECG AI inference service
  - Network AI inference service
  - Fusion decision service
  - ECG simulator
  - Network simulator
- **Infra containers**:
  - Mosquitto
  - Optional Node-RED

This gives each process a single responsibility and allows scaling or disabling components independently.

## 5) Docker Compose Service Blueprint

Recommended Compose services:

- `mqtt-broker`
- `ecg-sim`
- `network-sim`
- `ecg-ai`
- `network-ai`
- `fusion`
- `dashboard`
- `node-red` (optional profile)

Use:

- one shared internal network (`ioht-net`),
- named volumes for `logs` and optionally model cache,
- `depends_on` for startup ordering,
- environment variables for broker host, topic names, model paths.

## 6) Migration Sequence (Low Risk)

1. Extract a **shared Python package** for constants (topics, QoS, labels, log paths).
2. Move each executable script into its own app folder with a proper entrypoint (`python -m ...`).
3. Split dependencies into per-service requirements.
4. Add Dockerfiles per app and a root `infra/docker/docker-compose.yml`.
5. Move generated logs out of source folders into `storage/logs` volume.
6. Keep notebooks/training isolated under `training/` and out of runtime images.
7. Replace `.bat` with platform-neutral scripts and Compose commands.

## 7) Additional Standardization Recommendations

- Add `.env.example` with all runtime env vars.
- Add health checks per container.
- Add `Makefile` commands: `make up`, `make down`, `make logs`.
- Add CI checks for lint + smoke tests.
- Add model checksum/version metadata (`models/manifest.json`).

## 8) Immediate “Next Commit” Candidates

- Create `infra/docker/docker-compose.yml` skeleton.
- Add one initial Dockerfile for dashboard and one for a backend service.
- Introduce `apps/shared/ioht_common/topics.py` and refactor topic strings there.
- Move historic CSV logs from tracked files to ignored runtime storage.
