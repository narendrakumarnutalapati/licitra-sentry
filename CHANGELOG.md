# Changelog

## [0.2.0] - 2026-03-03

### Added
- **Witnessed Transparency Layer** (`app/witness.py`): CT-style public transparency log integration. Every epoch, the MMR root hash (plus policy hash, build hash, chain link) is submitted to an independent witness. The witness returns a Signed Inclusion Receipt (Ed25519) proving the epoch was observed. Receipts are stored per-epoch. External auditors can verify the complete evidence bundle using only the witness's public key — no trust in the operator required.
- **WitnessVerifier** (standalone auditor tool): Verifies receipt signatures, epoch digest consistency, chain continuity, monotonic sequencing, and timestamp ordering across all witnessed epochs.
- **Execution Ticket System** (`app/ticket.py`): Ed25519-signed tickets that cryptographically bind authorization decisions to specific tool request payloads. Tickets include request hash, agent identity, tool audience, policy version, contract reference, and MMR commit ID. Maximum 60-second TTL.
- **Tool Proxy Gateway** (`app/tool_proxy.py`): Mandatory mediation layer between agents and tools. Verifies ticket signature, expiration, audience match, request hash integrity, and replay protection before allowing execution.
- **Replay Protection**: SQLite-backed JTI tracking. Each ticket can only be used once.
- **Key Management** (`app/key_manager.py`): Ed25519 key generation, storage, and retrieval with abstract `KeyProvider` interface for future KMS/HSM integration.
- **External Anchoring** (`app/anchor.py`): Pluggable interface for anchoring MMR root hashes externally. File-based reference provider included. Designed for future Bitcoin OP_RETURN, Ethereum calldata, or RFC 3161 timestamp authority integration.
- **Rate Limiting**: Per-agent sliding window rate limiter in the Tool Proxy.
- **Payload Size Limits**: 1MB maximum request payload size.
- **Content Inspection Patterns**: PII detection (SSN, credit card), shell injection, SQL injection, path traversal.
- **Test Suite**: 13 reproducible experiments (E01–E13) covering authorized flow, proxy bypass, replay attack, payload modification, expired ticket, delegation escalation, PII exfiltration, audit chain integrity, epoch witnessing, operator rewrite detection, auditor verification, tampered receipt rejection, and chain break detection.
- **Demo Scripts**: `demo_ticket_execution.py` (3 scenarios) and `demo_witness.py` (witnessed epochs, attack detection, auditor verification).
- **Deployment Documentation**: Example Docker Compose and Kubernetes NetworkPolicy configurations.

### Changed
- Content inspector email pattern risk level changed from `high` to `medium` to avoid false positives on legitimate email tool requests.
- Orchestrator now issues execution tickets on successful authorization (Gate 5).

### Architecture
- Five-gate Chain of Intent pipeline preserved from v0.1
- New mandatory mediation model: agents → SENTRY → ticket → proxy → tool
- All gate decisions (pass and fail) committed to hash-chained audit ledger

## [0.1.0] - 2026-02-15

### Added
- Initial five-gate Chain of Intent authorization pipeline
- Identity verification (Gate 1)
- Content inspection (Gate 2)
- Semantic contract validation (Gate 3)
- Authority enforcement with delegation controls (Gate 4)
- Audit bridge for MMR integration (Gate 5)
- Technical report published: https://doi.org/10.5281/zenodo.18843784
