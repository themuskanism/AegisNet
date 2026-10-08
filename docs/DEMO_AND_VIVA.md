# Reproducible capstone demonstration

Use one API worker, the supplied trusted artifacts, PostgreSQL with migrations applied, and the built frontend. Start with capture stopped. Do not replay PCAP packets onto any network.

1. Launch `python -m scripts.serve`; visit http://127.0.0.1:8000. In **System Health**, show actual database engine and model version. Enter the local analyst token through the sidebar credential dialog.
2. Show **Model & Research**: four real experiments, split support, poor scan recall, confusion matrix, measured policy trade-off and timing. Explain the narrow single-scenario scope before demonstrating predictions.
3. In **Command Center**, choose the loopback interface and start monitoring. Generate normal localhost HTTP requests (the `scripts.verify_operational --live-loopback` command automates this separately). Stop monitoring; closing flows continue through inference. Show real flow rows, capture counters and queue/worker state.
4. Explain that malicious labels on safe local traffic are **false positives/domain shift**, not actual attacks. Do not claim a live intrusion was detected by this test.
5. With capture stopped, click **Benchmark replay**. This replays 12 held-out metadata flow fixtures internally; it sends zero packets. Inspect **Live Traffic** and the explicit **Benchmark replay** badges.
6. Open a replay incident: show traffic time versus ingestion time, source/destination, selected class/confidence, risk factors and model version. Request SHAP if it is not already ready. Inspect positive/negative contributions and the probability reconstruction. First explanation can be slower.
7. Click **Acknowledge**, provide a reason, confirm, and show the persisted state/action. Try a protected-address simulated block: refusal is expected and audited. In **Response Center**, create a MANUAL block proposal for a global example target, clearly described as a verification-only target; approve once, show `simulated`, then demonstrate an idempotent repeated API approval. No connection to the target is made.
8. Show automatic simulated recommendations/refusals on HIGH/CRITICAL incidents and the audit log. ACTIVE is unavailable.
9. Restart the API and show that flows/incidents/actions remain while process uptime and session counters reset. The UI never reports a stopped sensor as monitoring.

Automated verification: set `AEGIS_API_TOKEN` to the configured token and run `python -m scripts.verify_operational --live-loopback`. It requires the local API and PostgreSQL; writes a timestamped measured report to `artifacts/operational_evaluation.json`. It leaves reviewed/simulated records in the demo database and capture stopped.

## Phase explanations for the viva

| Phase | What / why / how | Verify | 30–60 second explanation |
|---|---|---|---|
| Capture + flows | Retained Scapy; bounded bidirectional connections replace CSV-only counting. | `tests/test_flows.py`; live loopback check | “A packet counter cannot represent an exchange. We group by an unordered endpoint pair and protocol, retain first-observed direction, and close by idle time, active time, transport closure or packet cap. Training and live code use the same feature function. We exclude unsupported/fragmented traffic and expose drops rather than silently inventing data.” |
| Dataset + models | Original labelled PCAP supports reproducible live features. Four classifiers measured. | dataset hashes, split tests, evaluation.json | “We do not copy benchmark CSV columns into a live model. We extract 20 metadata features from original packets, join labels conservatively, and prevent original connection and duplicate-feature groups crossing partitions. The CNN uses actual packet sequences. Random Forest wins validation macro F1, but minority-class and live-domain results limit the conclusion.” |
| Risk + XAI | Separate model belief, triage priority and attribution. | SHAP reconstruction test; policy_evaluation.json | “Confidence is a model probability; risk is a documented weighted priority score. SHAP explains the calibrated pipeline output using training background flows. Neither proves an attack. Our risk policy performed worse on this held-out comparison, which is why we report it honestly and do not enable real enforcement.” |
| Persistence + API | Durable evidence and bounded asynchronous workers. | PostgreSQL migrations; API tests; restart | “Capture only queues metadata. Flow, inference and explanation workers operate independently with bounded capacity and visible drops. PostgreSQL stores evidence, incidents and decisions. REST serves history; SSE signals current state. Missing model or database errors remain explicit, never benign results.” |
| Response | Audited simulation/manual decision lifecycle. | response tests and operational check | “HIGH/CRITICAL incidents generate simulation-only recommendations. Analysts can acknowledge, whitelist or approve pending simulations. Validation protects local-critical and whitelisted sources and repeats at approval. No arbitrary command strings execute. Active firewall effects stay disabled until crash recovery is validated.” |
| SOC interface | Seven original, evidence-driven screens using Figma tokens. | type/lint/build, browser checks | “The UI is an investigation workspace, not a marketing dashboard. Every number comes from persisted records, session counters or measured artifacts. It distinguishes replay, synthetic and live origins, stale connections and missing evaluations. Incident detail connects what, when, endpoints, classification, confidence, risk, explanation and response.” |

## Failure demonstrations

- Start without model artifacts in a separate local test environment: health says unavailable; captured flows persist without predictions. Do not delete the working artifacts for this demonstration.
- Invalid analyst token: mutation returns 401; no state change.
- Whitelist a global source then attempt block: refusal remains audited.
- Unsupported capture interface: validation error, no running sniffer.
- Backend disconnection: browser reports stale/unavailable data; action controls disable on failed refresh.
- XAI failure: incident explanation reports error, inference/capture can continue.

Do not present a UI screenshot as proof of an unseen attack, automated containment or enterprise-scale performance.
