# Agisnest implementation specification

Approved direction: evolve the existing Scapy/Flask prototype in this repository. User requested continuous implementation on 2026-10-07 after reviewing the audit. Do not stop at plan gates. No rewrite of unrelated working code.

## Boundaries
Python 3.12, Scapy metadata capture, bounded queues, bidirectional flows with 30s idle/120s active limits, shared offline/live extractor. IPv4/IPv6 TCP/UDP initially; unsupported packets counted. Length means IP-layer bytes; first observed packet defines forward direction. Reject nonfinite times; count out-of-order packets. Completed flows only; latency includes completion wait separately.

FastAPI exposes authenticated mutations, REST reads and SSE. PostgreSQL 18 via SQLAlchemy/Alembic is deployment persistence; SQLite is explicitly local/testing. Capture never waits for model, XAI or DB work. Errors and dropped work are visible. Inference unavailable is never benign. Store provenance: live, benchmark replay or synthetic fixture.

Train Logistic Regression, Random Forest, histogram gradient boosting on shared metadata features. Use benchmark PCAP plus original labels, not prototype CSV. CNN-BiLSTM uses bounded within-flow chronological packet sequences (direction, IP bytes, interarrival, flags), masks and the same partitions. Split by original connection/group, prohibit exact duplicate feature groups crossing partitions. Publish limitations of within-scenario evaluation. Fit transformations on train only; calibration on validation; held-out test untouched by model selection.

Persist feature schema, extractor policy, class mapping, version, dataset checksums, evaluation and predictions. Real model-compatible SHAP/LIME, with cached results and separate latency, never template values. Risk combines calibrated malicious probability, documented severity, recent recurrence and flow evidence. Simulation default; manual proposals require a distinct approve/reject step. Protected addresses and whitelist always override block. Active execution only behind explicit enablement and a supported validated adapter.

Seven original React/TypeScript screens: Command Center, Live Traffic, Incidents/detail, XAI Lab, Response Center, Model & Research, System Health. Figma tokens/layout before frontend implementation. All metrics real API/DB values or explicitly labeled fixtures. Unknown or unmeasured values remain unavailable.

Acceptance: tests for capture, flows, parity, model/preprocessing, risk, database/migrations, API, XAI, response and failure modes; frontend type/build checks; real capture attempt; measured benchmark experiments; reproducible safe offline replay demo; accurate limitations and research evidence. Do not claim full P0 completion if an external prerequisite prevents verification.
