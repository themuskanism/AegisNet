# Delivery status — 8 October 2026

DONE: preserved 1.x baseline; shared ip-flow-v3 extraction; benchmark preprocessing and grouped splits; three classical baselines and genuine temporal CNN-BiLSTM; validation-selected calibrated Random Forest; real SHAP; documented risk; PostgreSQL/Alembic persistence; bounded capture/inference/XAI workers; authenticated mutation APIs and SSE; seven connected React screens; safe simulation/manual approvals and audit; research, setup and viva guides.

VERIFIED: 42 backend tests; 4 frontend tests; TypeScript, ESLint and Ruff checks; production build; PostgreSQL 18.6 migration round-trip and persistence; Npcap loopback capture; held-out replay, SHAP reconstruction and idempotent manual simulation; all seven browser pages, incident detail, confirmation form and mobile navigation. See FINAL_REPORT.md and artifacts/*.json.

CURRENT: delivery checkpoint and archive. Architecture remains unchanged. Live monitoring starts stopped; ACTIVE enforcement is unavailable.

NEXT / LIMITS: cross-scenario validation, minority-class improvement and an analyst usefulness study. Production hardening (multi-user RBAC, durable outage spool, active firewall crash recovery) is outside this verified research implementation. Docker and hosted GitHub Actions need execution on their target environments.

The 93.67% test accuracy is single-scenario evidence, not live-network accuracy. Macro F1 is 63.95%; horizontal-scan recall is 2/15. Safe live HTTP generated false positives. The fixed risk policy selected more benign samples than the confidence-only comparator. These are reported limitations, not hidden failures.
