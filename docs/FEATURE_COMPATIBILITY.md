# Feature compatibility gate — ip-flow-v3

Dataset decision: IoT-23, CTU-IoT-Malware-Capture-34-1 (Mirai), official PCAP and original Zeek labels. This is a bounded benchmark scenario, NOT the whole IoT-23 corpus, CIC-IDS2017 or enterprise-network validation. Selected because original PCAP+labels can be processed with the same extractor as live Scapy. Supported classes determined after unambiguous label matching and split support checks.

Source: https://www.stratosphereips.org/datasets-iot23 ; DOI https://doi.org/10.5281/zenodo.4743746 (Zenodo API license cc-by-4.0). Original PCAP SHA256: 92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699.

| Dataset feature/source | Live equivalent | Transformation | Keep/drop | Reason |
|---|---|---|---|---|
| PCAP timestamps | packet.time | seconds; max-min | KEEP duration_s | Same extractor, not Zeek duration |
| PCAP transport | decoded TCP/UDP | 6/17 | KEEP protocol | Direct metadata |
| PCAP direction counts | first-observed tuple orientation | per-direction counts | KEEP fwd_packets,bwd_packets | Same policy offline/live |
| PCAP IP-layer bytes | len(IP/IPv6 layer) | directional sum | KEEP fwd_bytes,bwd_bytes | Explicit layer, excludes L2 |
| PCAP packet lengths | IP bytes | min/max/mean/population std | KEEP length_* | Shared statistics |
| PCAP interarrival | sorted within-flow timestamps | mean/population std in seconds | KEEP iat_* | Single packet becomes zero |
| PCAP TCP flags | decoded flags | count set SYN/ACK/RST/FIN/PSH | KEEP *_count | UDP contributes zero |
| Derived rate | counts/flow duration | zero duration -> zero rate | KEEP packets_per_s,bytes_per_s | Same zero policy |
| Derived direction ratio | backward/total packet count | fraction | KEEP direction_ratio | Shared orientation |
| Zeek duration/byte/count columns | different connection semantics | none | DROP as model inputs | Do not assume same features from names |
| IP, ports, UID, absolute timestamp | metadata available | none | DROP as model inputs | Avoid identity/time leakage; use only label alignment/audit |
| label/det_label | original ground truth | Benign or original detailed attack class | TARGET ONLY | Never an input |
| service, history, payload-derived fields | not extracted | none | DROP | No live equivalent implemented |

Flow limits: idle 30s, active 120s, max 256 packets; first observed direction; TCP RST/bidirectional FIN/new established SYN closure. Fragments and non-TCP/UDP are excluded. Sequences retain first 32 chronological packets, direction, log1p(IP bytes), log1p(interarrival), 5 TCP flag bits; zero padding and true length. Features are computed on completed bounded flows, not arbitrary prefixes.

Match a flow only when its complete time interval fits exactly one Zeek connection of the same unordered endpoint/protocol tuple within 1ms tolerance. Unmatched/ambiguous flows are excluded, counted and reported. All windows of a matched UID stay together. Identical feature vectors are unioned into the same split group, including connected UID groups. Deterministic group split 60/20/20; this is within-scenario generalization, not chronological or cross-scenario proof. Report class support and reject unsupported partitions. Train-only scaler; validation-only calibration/model selection; test evaluated once after selection. No oversampling before splitting.


