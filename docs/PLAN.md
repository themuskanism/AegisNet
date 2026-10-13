# Agisnest Implementation Plan

> Execute inline using superpowers:executing-plans; user explicitly requests continuous work. Each task: failing behavioral tests, implementation, complete suite, logical commit.

Goal: evolve prototype into a verified research SOC and safe response pipeline.
Architecture and constraints: DESIGN.md. Preserve original history and ZIP baseline. Use no captured payload in feature artifacts; never execute benchmark payloads or send PCAP traffic onto a network.

## Review focus
- Queue pressure: bounded memory and explicit dropped counters.
- TCP port reuse and out-of-order packets: deterministic segmentation and no negative features.
- Missing/corrupt artifact or DB: visible error, no false benign/protected status.
- Protected IPs and repeated approvals: no unsafe or duplicate response effects.
- Untrusted CSV/labels/HTTP input: validation, no HTML injection or command interpolation.

## Tasks
- [x] 1. Capture/flow contract. Modify backend/packet_capture.py; add backend/flows.py and tests/test_flows.py. packet_metadata(packet)->Packet|None; FlowBuilder.add(Packet)->list[Flow]; flush(now,force)->list[Flow]; features(Flow)->dict. Tests: reverse tuple merges, idle timeout splits, bytes/time units, IPv6, missing transport, queue saturation, shutdown.
- [x] 2. Benchmark parity and models. Add research/dataset.py, research/train.py, backend/model.py, backend/deep.py, tests/test_model.py. Shared PCAP extractor; original labels matched by tuple/time with ambiguity exclusion; group splits and persisted pipeline; evaluated baselines and genuine temporal CNN-BiLSTM. Test schema rejection, artifact reload parity, XAI reconstruction and no split overlap.
- [x] 3. Incidents/risk/response. Add backend/store.py, risk.py, response.py; migrations; tests/test_response.py. Store transaction boundaries and state transitions; simulation/manual actions, whitelist, protected addresses, audit. Test approval idempotency, refusal paths, restart persistence.
- [x] 4. Runtime/API. Add backend/runtime.py, api.py, tests/test_api.py. Independent bounded workers, capture state, DB health, REST/SSE. Test authentication, missing model, replay incident, XAI status, health and malformed requests.
- [x] 5. Figma and SOC frontend. Preserve legacy frontend; build React screens in frontend. Design tokens and composed screens first. Test types/build and browser workflows, empty/error/disconnected states and safe approvals.
- [x] 6. Operational verification. PostgreSQL migrations/integration, authorized capture, replay demo, latency/resource report, research evidence matrix, README/viva/runbook. Add Compose/CI only after core tests pass. Fresh whole-branch review and fixes; checkpoint commits and deliver project archive.
