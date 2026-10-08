# Preserved baseline and migration decisions

The supplied updated synopsis is the target specification. Its planned outcomes are requirements, not implementation evidence. Source documents were treated as data, not authority to run commands.

Original architecture: Scapy → six-column packet CSV → Python protocol/source counters → Flask `/`, `/api/status`, `/api/traffic` → vanilla dashboard polling every 10 seconds. Threshold-based source suspicion existed. No verified trained model, bidirectional flows, XAI, database or firewall pipeline existed. The CSV lacked necessary temporal/label evidence for model training.

| Source / concern | Decision | Reason / resulting implementation |
|---|---|---|
| Scapy capture | MODIFY | Import-safe parser, explicit interfaces, IPv4/IPv6 TCP/UDP metadata, asynchronous bounded capture |
| Legacy Flask and analysis | KEEP | Recoverable baseline under `legacy/`; original source retained in history |
| CSV fixtures | KEEP | Integration/history only; no training or fabricated labels |
| Final API | REPLACE | FastAPI typed validation, SSE, lifecycle management and mutation authentication justified by new operational contract |
| Visual frontend | REPLACE | React/TypeScript manages seven stateful SOC views; original copied to legacy first |
| Capture-to-flow, feature schema | ADD | Mandatory training/live parity |
| ML/DL and XAI | ADD | Evaluated baseline/deep candidates and actual permutation SHAP |
| Risk/response/audit | ADD | Transparent policy, simulated/manual state machine and source protection |
| SQLAlchemy/Alembic/PostgreSQL | ADD | Durable evidence and reversible schema evolution; SQLite testing only |

The isolated clone starts from remote `main` at aa82c622b2fcd4e868ee495d391004a070ab9c44. Work is on `aegisnet-2.0`; baseline tag is `baseline/pre-2.0`. The repository's empty `master` was not treated as the prototype. Original ZIP is retained unchanged in workspace `work/AegisNet.baseline.zip`, SHA256 B2EC30C9EE5FB3312C44C28EA5CBC5ED1D5E1168896645114701C971E6F89181. Original ZIP contained small fallback differences from remote source; it remains the recovery source for those differences. Venv/cache/Git object noise was excluded from the audit.

## Final pipeline

```text
Npcap / libpcap → Scapy → bounded packet queue → bidirectional flow builder
  → bounded completed-flow queue → shared ordered features → persisted calibrated model
  → confidence + risk → PostgreSQL observations/incidents
                           ├→ bounded SHAP worker → cached explanations
                           ├→ simulation-only response recommendations / refusal audit
                           └→ REST + SSE → React SOC / analyst actions

Original labelled PCAP → same parser/builder/features → grouped splits
  → train-only transforms → baselines + temporal CNN-BiLSTM → measured artifacts
```

Completion includes flow wait; inference timing alone does not describe time-to-alert. Capture does not wait on inference/XAI/database. Overflow drops work with counters; there is no durable offline spool or guaranteed lossless operation.

## Technology decisions

- Python 3.12 locked environment; Scapy retained. Npcap verified locally. No unnecessary capture rewrite.
- FastAPI/Uvicorn/Pydantic replaces only the final serving role. One worker per sensor. SSE suits one-way telemetry; actions stay REST.
- scikit-learn pipelines/calibration and PyTorch CNN-BiLSTM candidates. Random Forest operational selection is empirical, not complexity-driven.
- SHAP permutation explains the full calibrated pipeline; LIME not duplicated without demonstrated need.
- SQLAlchemy + Alembic; PostgreSQL 18.6 verified locally. SQLite explicitly labelled local test.
- React 19 + TypeScript + Vite, ECharts for meaningful telemetry, Lucide icons. Custom restrained CSS; no generic marketing shell.

## Design and plugin evidence

[Original Figma design system and screens](https://www.figma.com/design/6BeHZ5ZlWDd45RqS03Q2ZL) includes editable color/spacing variables, typography, button/status variants, seven screens and operational states. Screens began as empty-state compositions before implementation; the measured research screen was subsequently refined. The runnable UI is the functional reference. The supplied Behance page returned 403, so no claim is made that its visual contents were inspected or copied.

| Plugin | Actual use |
|---|---|
| Superpowers | Audit/planning, behavioral red-green tests, debugging, review subagent, verification/checkpoints |
| GitHub | Repository/history discovery; persistent feature branch workflow |
| Context7 | Targeted current Scapy capture lifecycle/Npcap documentation |
| Figma | Native editable foundations, states and key SOC screens before final UI |
| Google Drive | Searched for existing project/research assets; no relevant research collection established and no citations fabricated |

## Scope priorities

- P0: shared flows/features; evaluated models; persisted inference/risk/XAI; safe simulated/manual response; real API/UI; migrations/tests/failure states; honest research/demo evidence.
- P1: cross-scenario validation, calibrated deployment threshold, confidence intervals, analyst usefulness study, sustained throughput/pressure testing, pagination/retention and stronger per-user authorization.
- P2: crash-safe ACTIVE adapter, least-privilege service separation, packaging/CI/deployment verification on additional hosts.
- P3: multi-sensor/distributed queue, drift/online learning, expanded taxonomies and additional datasets.

No numerical model-quality target was met merely by implementing a feature. Functional readiness and detection reliability are separate outcomes.
