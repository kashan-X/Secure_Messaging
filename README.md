# Secure E2EE Messaging & File Sharing

End-to-end encrypted messaging and file-sharing system built with **React (Web Crypto API)** on the frontend and **Node.js / Express / MongoDB** on the backend. All encryption and decryption happens entirely client-side — the server only ever sees ciphertext, never plaintext or private keys.

🔗 **Source code:** https://github.com/kashan-X/Secure_Messaging.git

🎥 **Video demo:** https://drive.google.com/drive/folders/1Asr013Ww2w4C45clkBklhHlc_KgKZon-?usp=sharing

---

## Introduction

This project is a full-stack demonstration of a real end-to-end encrypted (E2EE) messaging protocol, built from scratch without relying on third-party crypto libraries — using only the browser's native **Web Crypto API** on the client and Node's built-in `crypto` module on the server.

It implements a custom **signed ECDH handshake** (similar in spirit to the Signal protocol) with key confirmation, replay protection, and per-message AES-256-GCM encryption, so that even if the server or database is fully compromised, an attacker only ever recovers ciphertext, IVs, and auth tags — never plaintext messages, files, or private keys.

The project also includes built-in attack simulations (MITM and replay attacks) and security event logging, making it a practical case study for secure protocol design, not just a chat app.

---

## Features

### 🔐 Core Cryptography
- **Identity keys** — Each user generates a P-256 (ECC) identity key pair client-side on registration. The private key never leaves the device; it's encrypted (PBKDF2 + AES-GCM, derived from the user's password) and stored locally in IndexedDB. Only the public key is sent to the server.
- **Signed ECDH handshake** — A custom 3-step handshake (`INIT` → `RESP` → `CONFIRM`) between two users, using ephemeral P-256 keys, ECDSA signatures over identity keys, HKDF key derivation, nonces, timestamps, and strictly increasing sequence numbers to defeat MITM and replay attacks.
- **Key confirmation** — Both parties derive and verify an HMAC-based confirmation tag before a session is marked `ACTIVE`, guaranteeing both sides derived the identical session key.
- **Message encryption** — Every message is encrypted with AES-256-GCM using a fresh 96-bit IV and authenticated metadata (sender, receiver, sequence, timestamp) as AAD. The server stores only `{ciphertext, iv, tag, sender, receiver, ts, seq}`.
- **Chunked file encryption** — Files are split into chunks (default 512 KiB), each independently encrypted with AES-256-GCM under a per-transfer derived key. The server stores only encrypted chunks and metadata, never raw file content.

### 👤 Authentication & Accounts
- Username/password registration and login with bcrypt password hashing.
- JWT-based session authentication for all API routes.
- Optional TOTP-based two-factor authentication hook (via `speakeasy`).
- Public-key lookup endpoint so peers can fetch each other's identity public key to verify signatures.

### 💬 Messaging & Files
- Real-time-style encrypted text messaging between registered users.
- Encrypted file upload/download with chunked transfer and integrity verification on reassembly.
- Replay protection: duplicate `(sender, receiver, seq)` combinations are rejected server-side (HTTP 409) and logged.

### 🛡️ Security Logging & Auditing
- Centralized audit logging (`logs` collection) for security-relevant events, including:
  - `auth.success` / `auth.fail`
  - `handshake.init` / `handshake.resp` / `handshake.confirm` / `handshake.reject`
  - `decrypt.fail`, `signature.invalid`, `replay.detected`
  - `metadata.access`
- Client-reported security events (e.g. failed decrypts, invalid signatures) are sent to the server and logged for forensic review.

### ⚔️ Attack Demonstrations (Built-in)
- **MITM simulation** — An included attacker script demonstrates that an unsigned Diffie-Hellman exchange can be hijacked, while the signed handshake used in this project correctly detects and rejects the forged key exchange (`signature.invalid`, session aborted).
- **Replay simulation** — Re-sending a previously captured encrypted payload is detected and rejected by the server (and independently by the client via sequence-number enforcement), with the event logged.

### 📄 Documentation
- `docs/protocol.md` — Full cryptographic protocol specification (handshake, message/file encryption, key derivation).
- `docs/threat-model.md` — STRIDE-based threat model covering spoofing, tampering, repudiation, information disclosure, DoS, and privilege escalation, with mitigations and residual risks.
- `docs/attacks.md` — Step-by-step instructions for reproducing the MITM and replay attack demonstrations.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Web Crypto API, IndexedDB (via `idb`), Axios, Lucide Icons |
| Backend | Node.js, Express, MongoDB (Mongoose), JWT, bcryptjs, Helmet, CORS, express-rate-limit |
| Crypto | Native Web Crypto API (client) + Node `crypto` (server) — no third-party crypto libraries |
| 2FA | Speakeasy (TOTP) |

---

## Project Structure

```
Secure_Messaging-main/
├── backend/
│   ├── src/
│   │   ├── routes/        # auth, users, messages, files, logs, mitm demo
│   │   ├── models/        # User, Message, File, Log schemas
│   │   ├── middleware/     # JWT auth middleware
│   │   └── utils/          # audit logging helpers
│   ├── attack-scripts/    # MITM attacker simulation
│   └── .env.example
├── frontend/
│   ├── src/                # React app, Web Crypto handshake/encryption logic
│   └── components/        # UI components (incl. MitmDemo)
└── docs/
    ├── protocol.md
    ├── threat-model.md
    └── attacks.md
```

---

## Getting Started

### Prerequisites
- Node.js (v18+ recommended)
- MongoDB (local instance or MongoDB Atlas)
- A modern browser with Web Crypto / IndexedDB support (Chrome, Edge, Firefox)

### 1. Clone the repository
```bash
git clone https://github.com/kashan-X/Secure_Messaging.git
cd Secure_Messaging
```

### 2. Backend setup
```bash
cd backend
cp .env.example .env
npm install
npm run dev
```
The API will start on `http://localhost:4000`.

Edit `.env` if needed:
```
PORT=4000
MONGO_URI=mongodb://localhost:27017/e2ee
JWT_SECRET=change-me
CLIENT_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
TOKEN_TTL=1h
MAX_JSON_SIZE=15mb
```

### 3. Frontend setup
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
The app will be available at `http://localhost:5173`.

### 4. Try it out
1. Register a user — this generates and locally stores your identity key pair.
2. Open a second browser (or incognito window) and register a second user.
3. From one account, start a chat with the other — this triggers the signed ECDH handshake.
4. Once the session is `ACTIVE`, send encrypted messages and files between the two accounts.
5. Inspect the `messages` collection in MongoDB Compass to confirm only ciphertext/IV/tag are stored server-side — never plaintext.

---

## Attack Demonstrations

See [`docs/attacks.md`](docs/attacks.md) for full step-by-step instructions, including:
- Demonstrating that the signed handshake blocks MITM key substitution (and what happens if signature verification is disabled).
- Demonstrating that replayed message payloads are rejected via sequence-number and server-side duplicate detection.

---

## Security Design

Full protocol details and a STRIDE threat model are documented in:
- [`docs/protocol.md`](docs/protocol.md)
- [`docs/threat-model.md`](docs/threat-model.md)

Key design principles:
- No plaintext or private key material ever touches the server.
- All cryptographic primitives come from native, audited implementations (Web Crypto / Node `crypto`) — no custom crypto algorithms.
- Every message and file chunk is independently authenticated (AES-GCM) and bound to metadata via AAD to prevent tampering.
- Sessions require mutual key confirmation before being marked active.

---

## Disclaimer

This project was built as an academic/learning exercise in secure protocol design and is intended for demonstration purposes. While it implements real cryptographic best practices (signed ECDH, AES-256-GCM, HKDF, replay protection), it has not undergone a formal third-party security audit and should not be used as-is for production-grade confidential communications.
