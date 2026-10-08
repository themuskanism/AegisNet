# Research evidence and measured limitations

Review updated 2026-10-08. Evidence is distinguished from our interpretation. This is a focused review, not a systematic literature review or a novelty claim.

| Question / proposed gap | Primary evidence | What it supports; what it does not |
|---|---|---|
| Offline scores versus operational validity | Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022. [Paper and proceedings](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) | Documents methodological pitfalls in security ML. Motivates leakage controls and operational measurement; does not quantify how many NIDS products lack live integration. |
| Dataset and temporal shift | Pendlebury et al., *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time*, USENIX Security 2019. [Proceedings](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury) | Demonstrates spatial/temporal evaluation bias in malware classification. Transfer to network detection is our methodological inference, not that paper's NIDS result. |
| Analyst-facing explanations | Lundberg & Lee, *A Unified Approach to Interpreting Model Predictions*, 2017. [Paper](https://arxiv.org/abs/1705.07874) | Provides feature attribution framework. Does not establish that our explanations improve analyst decisions. Our additivity check and overhead measurements are technical evidence only. |
| Alternative local explanation | Ribeiro, Singh & Guestrin, *“Why Should I Trust You?”: Explaining the Predictions of Any Classifier*, 2016. [Paper](https://arxiv.org/abs/1602.04938) | Defines LIME, a legitimate alternative. This implementation uses real permutation SHAP; LIME is not claimed implemented. |
| Detection/response integration already exists | [Suricata IPS concept](https://docs.suricata.io/en/latest/ips/ips-concept.html) and [exception policies](https://docs.suricata.io/en/suricata-8.0.4/configuration/exception-policies.html) | Official documentation describes drop/reject enforcement and exception handling. It contradicts any claim that detection and response have never been integrated. Our contribution is the particular reproducible ML/XAI/research workflow. |
| Benchmark availability and labels | Garcia, Parmisano & Erquiaga, *IoT-23: A labeled dataset with malicious and benign IoT network traffic*, 2020, v1.0.0. [Dataset DOI](https://doi.org/10.5281/zenodo.4743746), [creator documentation](https://www.stratosphereips.org/datasets-iot23) | Original PCAP and labelled Zeek connections enable compatible feature re-extraction. Original labels are reused; we do not claim independent attack-ground-truth verification. Dataset licence: CC BY 4.0 in Zenodo record. |

Defensible contribution: an integrated single-sensor capstone that measures a shared PCAP/live feature pipeline, calibrated classification, local attribution, persistent incidents and controlled response. “Limited integration in the reviewed work” is defensible only for an enumerated comparison corpus; this small review does **not** establish prevalence. No “first ever”, zero-day or enterprise-readiness claim is supported.

## Experimental design

IoT-23 scenario CTU-IoT-Malware-Capture-34-1 was chosen for accessible original packets plus explicit labels, after rejecting direct use of unavailable/live-incompatible dataset columns. It is a bounded feasibility study, not all of IoT-23. The compatibility matrix precedes training in [FEATURE_COMPATIBILITY.md](FEATURE_COMPATIBILITY.md).

5,520 matched flows; 2,810 unmatched/ambiguous flows excluded. The exact source checksums and class support are in `artifacts/dataset_manifest.json`. Features are recomputed from IP metadata; labels join by unordered tuple and complete time containment within exactly one original connection. UID and duplicate-feature union groups cannot cross splits. The resulting row counts are 4,177 train, 664 validation, 679 test (group fractions, not row-stratified fractions). Excluding ambiguous flows can introduce selection bias.

Training-only StandardScaler is persisted with each tabular estimator. Logistic regression uses class weights; Random Forest uses balanced weights; histogram gradient boosting is an unweighted baseline. Validation is reused for sigmoid calibration and model comparison; this can favor validation results. The held-out test is not used to select the operational model or tune risk weights.

The CNN-BiLSTM sees chronological packets rather than pretending feature columns are time. It uses first 32 packets, 8 metadata channels, Conv1d(8→24, kernel 3), bidirectional LSTM(24), packed lengths, a classification head, weighted training loss and validation temperature calibration. Twelve epochs are evaluated. This is one defensible candidate, not an exhaustive architecture/hyperparameter search.

## Results frozen in evaluation.json

| Model | Accuracy | Macro precision | Macro recall | Macro F1 | Benign FPR |
|---|---:|---:|---:|---:|---:|
| Logistic Regression | 92.34% | 57.43% | 71.81% | 59.80% | 9.41% |
| Random Forest (operational) | 93.67% | 63.34% | 69.16% | 63.95% | 9.41% |
| Histogram Gradient Boosting | 94.40% | 58.43% | 67.55% | 61.29% | 7.06% |
| CNN-BiLSTM | 90.87% | 54.57% | 71.55% | 57.34% | 10.20% |

The frontend displays exact measured precision/recall, per-class support and confusion matrices. Random Forest was selected using **validation macro F1**, not the test accuracy column. Scan recall is only 2/15 (13.33%) in the held-out test. The apparently strong C&C score is within a single scenario; it must not be generalized to arbitrary C&C traffic.

**Domain shift is already visible:** the safe loopback HTTP verification generated malicious predictions on benign local activity. This proves pipeline operation, not reliable live threat detection. The model requires cross-scenario and deployment-specific calibration before operational use. The UI calls these model incidents, not confirmed attacks.

## Operational and policy experiments

`artifacts/operational_evaluation.json` records real Npcap loopback capture, normal local HTTP, PostgreSQL writes, real SHAP probability reconstruction, manual approval/idempotency and zero firewall blocks. Flow completion wait, queue wait and feature/inference/database service time are distinct. Model batch throughput must not be represented as end-to-end link capacity. RSS is a sampled process value, not peak memory.

`artifacts/policy_evaluation.json` compares fixed confidence ≥0.90 recommendations against risk ≥65 on the same held-out set, with original-timestamp five-minute recurrence. Confidence-only recommended 393 flows (3 benign); risk recommended 184 (23 benign). Malicious coverage fell from 91.98% to 37.97%. **Risk-v1 did not improve this benchmark trade-off.** Report this negative result; do not tune on this test set and republish it as untouched. The risk score remains transparent triage information; simulations and analyst approval constrain consequences.

SHAP uses 16 training-background rows and 82 evaluations per explained sample over the full calibrated pipeline. Contributions describe model associations, not causality or packet-forensic proof. Cold and warm latency differ substantially. No analyst usefulness study, significance study or attribution-stability study has been performed.

## RQ status and next evidence

- RQ1: measured within scenario. Add independent scenarios and uncertainty intervals before broader conclusions.
- RQ2: four measured models; CNN did not outperform the best baseline in macro F1. Representations differ and are documented.
- RQ3: shared extraction, artifact schema checks, exact replay feature equality and group tests implemented. Capture-point effects, packet loss and offload can still shift real features.
- RQ4: real SHAP and measured overhead/additivity; user usefulness remains an empirical study.
- RQ5: model batch/single timing and functional live pipeline timing measured. Sustained throughput/backpressure testing remains.
- RQ6: fixed policy comparison and sensitivity results measured; no superiority claim. No real blocking experiment.
