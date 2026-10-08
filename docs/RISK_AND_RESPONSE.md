# Risk and response contract

Risk-v1 is an **ordinal triage score**, not a calibrated probability of compromise.

For a non-Benign prediction:

`score = 100 × (0.35 P(malicious) + 0.30 severity + 0.20 recurrence + 0.15 evidence)`

- `P(malicious) = 1 - P(Benign)` from the persisted calibrated classifier. This differs from selected-class confidence.
- Severity: DDoS 1.0, C&C 0.8, horizontal scan 0.5. These are explicit expert priorities for disruption, persistent command activity and reconnaissance; they are not universally established numerical facts.
- Recurrence: previous incidents from the same source and same provenance in 300 seconds, divided by 10 and capped at 1. Live/replay recurrence is based on ingestion time; offline policy evaluation uses original capture time and declares that difference.
- Evidence: half the packet rate divided by 100 and capped at 1, plus half for a flow with at least three forward packets and no backward packets. The rate denominator is at least one second, avoiding infinite scores on one-packet flows.
- Bands: LOW <40, MEDIUM 40–<65, HIGH 65–<85, CRITICAL ≥85. Benign predictions return zero with an explicit “not proof of safety” advisory.

Weights keep model belief the largest individual factor, while contextual factors collectively outweigh it. The limits bound recurrence/rate effects. These design rationales make the score explainable; they do **not** validate its operational utility. See the negative policy result in RESEARCH.md. No tuning to the held-out test has been performed.

HIGH/CRITICAL incidents trigger independent XAI and an automatic **SIMULATION** block recommendation. Address protections still apply; refusals are audit events, not real blocks. Recommendations never issue firewall commands.

| Mode/action | Actual behavior |
|---|---|
| SIMULATION block/unblock | Persist decision with `simulated` state; no blocked-source row or OS change |
| MANUAL block/unblock | Persist `pending`; separate approval/rejection; approved result is simulated |
| Whitelist/unwhitelist | Persist source policy change immediately, with reason |
| Acknowledge/ignore | Persist incident state; incident/source identity must match |
| ACTIVE | Refused even if an environment flag is set. External-effect recovery/reconciliation has not been validated |

Global-IP validation and local/private/multicast protection precede every block. A whitelist is checked again at approval. Address strings never enter a shell. Repeated approval is idempotent. Failed validation is logged. The audit table is append-style in application code, **not** a cryptographically immutable or privileged-administrator-proof ledger. Single API worker is required; this is a local single-analyst token model, not multi-tenant RBAC.

Future active response needs durable intent, unique firewall rule identity, crash reconciliation, concurrent-request coordination, explicit environment-specific allow/protect lists and rollback tests. The existing argument builder is not evidence that an active adapter is production-ready.
