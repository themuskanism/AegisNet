# Execution ledger — docs/PLAN.md

DONE: source/synopsis audit; remote main aa82c62 cloned, baseline/pre-2.0 tagged; isolated aegisnet-2.0 branch. Original ZIP copied to workspace work/AegisNet.baseline.zip (SHA256 B2EC30C9EE5FB3312C44C28EA5CBC5ED1D5E1168896645114701C971E6F89181).
CURRENT: task 1 capture/flows.
NEXT: benchmark compatibility and experiments.
BLOCKED: none yet; Npcap/PostgreSQL/dataset access not established.
Ruling: execute continuously inline without further plan confirmation, following explicit user instruction.
Ruling: isolated fresh clone on feature branch provides isolation; do not create a redundant nested worktree.
Preflight: flow schema is shared by research/train and runtime/model. Response consumes persisted incidents, frontend consumes API JSON. Freeze each contract with tests before downstream work.
