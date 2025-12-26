# Secure E2EE Messaging + File Sharing

End-to-end encrypted messaging and file sharing system built with React (Web Crypto) and Node.js/Express + MongoDB. All encryption happens client-side; servers never see plaintext or private keys.

## Highlights
- Identity keys: P-256 (ECC) identity key pair generated client-side; private key stays in IndexedDB (encrypted).
- Session setup: Custom signed ECDH handshake + HKDF, with nonces, timestamps, sequence numbers, and key-confirmation MAC to block MITM/replay.
- Messaging: AES-256-GCM per message with fresh IV + auth tag; metadata only on server (ciphertext, iv, tag, sender, receiver, ts, seq).
- Files: Client-side chunked AES-256-GCM encryption; only encrypted chunks + metadata stored.
- Logging: Auth attempts, key exchanges, replay rejections, signature failures, failed decrypts, metadata access.
- Attacks: MITM/replay simulations + proofs that signatures/timestamps/seq-numbers prevent them.

## Planned Layout
- `backend/`: Express + MongoDB API for auth, metadata, logging, and relay of E2EE payloads.
- `frontend/`: React app using Web Crypto for key generation/storage, handshake, encryption, replay protection, and UI.
- `docs/`: Protocol flow, threat model (STRIDE), attack demos, and diagrams.

## Build Stages (mapped to requirements)
1) Design docs: protocol, threat model, attack/demo plan.  
2) Backend scaffold: auth + metadata API, logging, key-exchange endpoints (no plaintext).  
3) Frontend crypto core: keygen/storage, signed ECDH + HKDF, message/session management, replay protection.  
4) File sharing: chunked AES-GCM upload/download, metadata handling.  
5) Attacks/tests: MITM/replay scripts, logging verification, report polish.

## Next Steps
- Finalize protocol spec (`docs/protocol.md`) and STRIDE (`docs/threat-model.md`).
- Run dev servers:
  - `cd backend && cp .env.example .env && npm run dev`
  - `cd frontend && npm run dev` (uses Vite; API defaults to `http://localhost:4000`)
- Client flow: register (generates/stores identity keys locally) → login → handshake (INIT/RESP/CONFIRM) → send encrypted text → upload/download encrypted file chunks.
