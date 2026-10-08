# Final implementation and verification report

Date: 8 October 2026. Status: integrated, demonstrable research capstone; not a production intrusion-prevention appliance.

## Completed

- Existing prototype preserved in legacy/ and baseline/pre-2.0. Work continues on aegisnet-2.0, leaving main untouched.
- Npcap/Scapy TCP/UDP capture, bidirectional bounded flows, correct IP-layer byte lengths, shared training/live feature schema and persisted calibrated preprocessing.
- IoT-23 scenario 34 PCAP/label preparation, group-separated train/validation/test data, evaluated Logistic Regression, Random Forest, histogram gradient boosting and packet-sequence CNN-BiLSTM. Model artifacts are delivered.
- Random Forest selected by validation macro F1; real class probabilities, documented risk factors, on-demand/cached permutation SHAP and recorded explanation time.
- FastAPI/SSE, PostgreSQL 18.6, Alembic, incidents, actions, protected sources, audit records, bounded independent worker queues and visible error states.
- Seven original React/TypeScript SOC pages connected to the backend. Incident detail includes endpoints, timestamps, prediction, risk, actual SHAP, related detections, actions and advisory.
- Simulation, manual approvals, whitelist and incident state management. Active firewall execution is disabled even if requested; no firewall rules were changed.
- README, reproducible data/training commands, research evidence and limitations, feature matrix, response formula, professor demonstration and viva guide, optional PostgreSQL Compose and CI configuration.

## Verification evidence

- Backend: `python -m pytest -q` — 42 passed in 45.80 seconds; one Starlette/httpx deprecation warning.
- Frontend: `pnpm --dir frontend test` — 4 passed across 3 files. TypeScript and ESLint passed.
- Python static checks: Ruff F rules passed for backend, research, tests and scripts.
- Production build: Vite completed, 609 modules; JavaScript 695.05 kB (228.33 kB gzip). Bundle-size warning remains; no build error.
- PostgreSQL: migration upgrade/downgrade/upgrade, reconnect persistence and repeated approval idempotency passed on a separate disposable database. See artifacts/postgres_verification.json.
- Operational run: actual loopback HTTP capture, persisted predictions, 12 metadata replay flows, genuine SHAP reconstruction and manual simulation. See artifacts/operational_evaluation.json for measured timings and run scope.
- Browser: Command Center, Live Traffic, Incidents, XAI Lab, Response Center, Model & Research and System Health rendered real records; incident SHAP and response form inspected; mobile navigation checked at 390x844. SSE connected. After process restart, persisted records remained visible.
- Launcher: repaired PowerShell's process-tree wait so PostgreSQL can remain running while the API starts; HTTP health returned 200 and database/model were ready.

## Actual model results and research limits

Held-out Random Forest: accuracy 93.67%, macro precision 63.34%, macro recall 69.16%, macro F1 63.95%, false-positive rate 9.41%. Test set: 679 flows from one scenario. Horizontal-scan recall: 2/15. CNN-BiLSTM macro F1: 57.34%; it was not promoted over the stronger validation-selected baseline.

No cross-scenario or enterprise validation, no zero-day claim, and no analyst usefulness study. Live benign HTTP produced false positives. The fixed risk policy selected 23 benign test samples versus 3 for confidence >=0.9; this experiment does not establish improved blocking safety. Evaluation and policy JSON contain the full measured results.

## Remaining work and environment limits

- Cross-scenario/generalization experiments and minority-class improvement require further research; they cannot be replaced by a claim of live accuracy.
- Active OS firewall execution requires transactional crash-recovery and platform validation. Simulation/manual-to-simulation are implemented and tested.
- Docker Compose and hosted GitHub Actions are configured but were not executed in those environments.
- No multi-user RBAC, tamper-proof audit, durable database-outage spool or production link-capacity certification.
- Figma is an editable design system and screen composition reference; the runtime includes additional operational detail.

Estimated completion: **95% of the requested research-capstone deliverable**, a judgment based on implemented and tested functionality, not a measured metric. The remaining validation and optional active-enforcement work prevent a 100% claim.

## Run on this configured computer

From the project directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\Start-AegisNet.ps1
```

Open http://127.0.0.1:8000. Use the local `data/analyst-token.txt` in Configure analyst token. Do not share it. The server is loopback-only and capture starts stopped. If it is already running, simply open the dashboard rather than launch a second server.

For another computer, follow README.md: Python 3.12/uv, PostgreSQL 18, `uv sync --locked`, database URL, `uv run alembic upgrade head`, then `uv run python -m scripts.serve`. The archive includes the built UI; a Git checkout requires the documented pnpm install/build. Npcap/libpcap and appropriate capture privileges are needed only for live capture.

## Professor demonstration

1. Open System Health and confirm PostgreSQL, classifier, workers and SSE.
2. Show Model & Research: real metrics, confusion matrix, weak classes and negative policy result.
3. Configure the analyst token. Select an authorized interface, start capture and generate ordinary HTTP traffic; observe flows, then stop capture.
4. Run Benchmark replay. Explicitly explain that these are held-out metadata records and no network packets are transmitted.
5. Inspect an incident: what/when/endpoints/classification/confidence/risk and genuine SHAP. Discuss association versus causation.
6. Acknowledge with a reason. Create a MANUAL block proposal for a public-address simulation target and approve it; verify simulated status and audit trail. Local/private addresses must be refused.
7. Refresh/restart to demonstrate persistence. Finish with limitations, not a production-security claim.

See docs/DEMO_AND_VIVA.md for detailed walkthroughs and 30–60 second explanations.
