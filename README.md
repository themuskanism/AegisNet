# AegisNet 2.0

A single-sensor research SOC connecting Scapy capture, shared flow features, evaluated intrusion classifiers, real SHAP explanations, persistent incidents and controlled response.

**Status:** functional research implementation. Predictions are not confirmed attacks. The benchmark covers one IoT-23 scenario; live benign loopback traffic generated false positives. Simulation is the default and ACTIVE firewall execution is disabled. Read [research limits](docs/RESEARCH.md) before interpreting performance.

## Start the existing project

On the already configured Windows workspace, run `powershell -ExecutionPolicy Bypass -File .\Start-AegisNet.ps1` from this folder. It reuses the existing PostgreSQL cluster, model, dependencies and built dashboard. No rebuild or training is needed. Keep the terminal running. The portable cluster is workspace-specific and is not included in the delivery archive; use the setup below on another machine.

Requirements: Python 3.12, Node.js 22.13+ (24 tested), pnpm 11.19, PostgreSQL 18, and Npcap on Windows (or libpcap/capture privileges on Linux). Use the lockfiles. The original prototype is preserved under `legacy/` and tag `baseline/pre-2.0`.

```powershell
uv sync --locked
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
```

Create a PostgreSQL database/user dedicated to this project. Set the connection URL in the environment, then apply migrations:

```powershell
$env:AEGIS_DATABASE_URL = 'postgresql+psycopg://aegis:YOUR_PASSWORD@127.0.0.1:5432/aegisnet'
uv run alembic upgrade head
uv run python -m scripts.serve
```

Open http://127.0.0.1:8000. The launcher generates `data/analyst-token.txt` if no `AEGIS_API_TOKEN` is configured; paste that token into **Configure analyst token**. It is stored only for that browser tab session. Keep the token private. The launcher also reads optional `.env` (see `.env.example`); environment variables take precedence. Alembic itself reads the environment, not `.env`.

For a lightweight local test, omit `AEGIS_DATABASE_URL`; the application explicitly reports SQLite local test mode. PostgreSQL is the verified deployment database. Use one Uvicorn worker. The launcher binds only to loopback; do not publicly expose this single-analyst development API.

The delivered archive includes trusted trained artifacts and the built UI. A source checkout must include/recreate `artifacts/model.joblib`, `metadata.json`, `demo.json` and `evaluation.json`. Joblib artifacts are executable serialization: load only your own trusted training outputs. Checksum/schema validation detects accidental mismatch, not malicious replacement of both files.

## Safe demonstration

1. Check **System Health** and **Model & Research**.
2. Start monitoring on an authorized interface; stop before replay. Capture starts stopped.
3. Click **Benchmark replay** for 12 held-out metadata flows; zero network packets are sent.
4. Open an incident, inspect confidence/risk, request genuine SHAP and acknowledge with a reason.
5. Review simulated responses and manual approvals in **Response Center**. Protected-address refusals are expected. No firewall rule is changed.

Detailed [demo and viva guide](docs/DEMO_AND_VIVA.md), [risk/response contract](docs/RISK_AND_RESPONSE.md), [architecture/audit](docs/ARCHITECTURE_AND_AUDIT.md), [feature compatibility](docs/FEATURE_COMPATIBILITY.md), and [progress/evidence](docs/PROGRESS.md).

## Reproduce the research

```powershell
uv run python -m scripts.download_dataset
uv run python -m research.dataset
uv run python -m research.train
uv run python -m research.policy_evaluation
```

The download command retrieves only the documented PCAP and labels, verifies SHA256, and never runs malware or sends captured traffic. IoT-23 attribution/licence and methodology are in [RESEARCH.md](docs/RESEARCH.md). Generated raw data/caches are excluded from Git. Restart the API after replacing model artifacts. Old incidents retain their original model version; explanations cannot silently use a different model.

The dataset contract is `ip-flow-v3`: 20 metadata features and one ordered schema for training and live inference. IP lengths exclude link padding; truncated/fragmented and unsupported packets are excluded. The original CSV is not a training benchmark. CNN-BiLSTM uses first-32-packet sequences, not feature-column pseudo-time. Operational model selection uses validation macro F1, not test performance.

Measured results live in `artifacts/evaluation.json`; operational timing is separately in `operational_evaluation.json`; fixed policy comparison/sensitivity is in `policy_evaluation.json`. The dashboard reads these artifacts through the API. It never substitutes invented results for missing files.

## Tests and verification

```powershell
uv run pytest -q
uv run ruff check backend/flows.py backend/packet_capture.py backend/model.py backend/deep.py backend/store.py backend/response.py backend/risk.py backend/runtime.py backend/api.py research tests scripts --select F
pnpm --dir frontend check
pnpm --dir frontend test
pnpm --dir frontend lint
pnpm --dir frontend build
```

With the API running on PostgreSQL and `AEGIS_API_TOKEN` set:

```powershell
uv run python -m scripts.verify_operational --live-loopback
```

That opt-in check captures ordinary local HTTP, persists real predictions, explains a replay incident and approves a simulation. It leaves auditable verification records and stops capture. No malicious traffic is required. Timing is a functional local run, not enterprise throughput. The dependency lock currently emits a Starlette/httpx TestClient deprecation warning; tests remain valid and the warning is recorded.

## Important boundaries

- Only IPv4/IPv6 TCP/UDP metadata flows; no fragment reassembly, payload analysis, zero-day guarantee or brute-force-class claim.
- Single-scenario evaluation with group-separated splits. Dataset/live domain shift is observed; minority-class performance is weak.
- Risk-v1 is a transparent heuristic; measured policy comparison does not establish improved blocking safety.
- Bounded queues and drop/error counters; database outage is visible but there is no durable retry spool. Shutdown drains workers and may wait for SHAP.
- Simulation/manual approvals implemented. Active OS enforcement is deliberately unavailable pending crash-recovery validation.
- Append-style audit, local bearer token, no multi-user RBAC or tamper-proof ledger.
- Figma contains the original editable design system and screen compositions: https://www.figma.com/design/6BeHZ5ZlWDd45RqS03Q2ZL

Do not use this capstone as an unattended production firewall or infer compromise from its live predictions alone.
