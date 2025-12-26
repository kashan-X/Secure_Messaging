# Protocol & Crypto Design

## Goals & Constraints
- E2EE for messages/files: ciphertext-only on server; AES-256-GCM with fresh IV per message/chunk.
- Identity: per-user P-256 key pair (Web Crypto) generated client-side; private key never leaves device and is stored encrypted in IndexedDB.
- Authentication: username/password with bcrypt/argon2 on server. Session cookie/JWT for API access. Optional TOTP 2FA hook.
- No third-party crypto libs; browser Web Crypto + Node `crypto`.

## Identity & Storage
- On registration: generate P-256 key pair `idPriv/idPub`. Encrypt `idPriv` with a key derived from user password (PBKDF2 310k iterations, salt, AES-GCM) before storing in IndexedDB. Server only receives `idPub`.
- Session secrets and nonces are cached in IndexedDB (or memory) with rolling counters per peer to enforce replay protection.

## Custom Signed ECDH Handshake (with Key Confirmation)
Notation: `A` initiator, `B` responder, `||` concat, `SigX(m)` ECDSA over SHA-256 using identity key of `X`, `HKDF(salt, ikm, info, len)`.

Shared parameters: curve `P-256`, `info` string `"e2ee-handshake-v1"`, time skew ≤120s, sequence numbers strictly increasing per (peer, direction).

Transcript hash: `H = SHA256(A_id || B_id || A_eph || B_eph || nonceA || nonceB || tsA || tsB || seqA || seqB)`.

### 1) INIT (A → B via server relay)
Fields:
- `aid`: sender id
- `bid`: receiver id
- `A_id_pub`: identity public key (cached by B after first contact)
- `A_eph_pub`: ephemeral P-256 public key
- `nonceA`: 96-bit random
- `tsA`: unix ms
- `seqA`: initiator sequence number
- `alg`: `"P-256+HKDF+AES-256-GCM"`
- `sigA`: `SigA(A_eph_pub || nonceA || tsA || seqA || bid || alg)`

Validation (B): check signature with `A_id_pub`, timestamp window, seq monotonic, nonce freshness. Log failures.

### 2) RESP (B → A)
- Generate `B_eph_priv/publ`, `nonceB`, `tsB`, `seqB`.
- Compute shared secret: `Z = ECDH(B_eph_priv, A_eph_pub)`.
- Derive: `k_master = HKDF(salt = nonceA || nonceB, ikm = Z, info, len = 96 bytes)` then split:
  - `k_enc` (32B AES-256-GCM), `k_file` (32B AES-256-GCM for file derivations), `k_confirm` (32B HMAC-SHA-256).
- `sigB`: `SigB(B_eph_pub || nonceB || tsB || seqB || aid || alg)`.
- `confirmB`: `HMAC(k_confirm, "B|" || H)`.

Response payload:
- `B_eph_pub`, `nonceB`, `tsB`, `seqB`, `sigB`, `confirmB`.

Validation (A): check signature, timestamp, seq, nonce, then recompute `H` and `confirmB`.

### 3) CONFIRM (A → B)
- `confirmA = HMAC(k_confirm, "A|" || H)`.
- Payload: `confirmA`, `tsA2`, `seqA2`.

B validates `confirmA`; both sides mark session `ACTIVE`. Failed confirms are logged and session is discarded.

### Replay/MITM Protections
- Signatures bind identities to ephemeral keys; MITM cannot swap ECDH keys.
- Nonces + timestamps + per-peer sequences are cached (sliding window, e.g., last 100) to reject replays.
- Final confirmation MAC assures both parties derived the same key.

## Message Encryption (E2EE)
Per message:
- Inputs: `k_enc`, plaintext, metadata `{aid, bid, seq, ts}`.
- `iv`: 96-bit random from `crypto.getRandomValues`.
- `aad`: JSON canonical bytes of metadata.
- `ciphertext, tag = AES-256-GCM(k_enc, iv, plaintext, aad)`.
- Server stores only `{ciphertext, iv, tag, aid, bid, ts, seq}`.

Decryption validates GCM tag and metadata (seq/timestamp freshness). Failed decrypts or invalid seq are logged and message is dropped.

## File Encryption (Chunked)
- File key per transfer: `k_file_xfer = HKDF(k_file, salt = fileId, info = "file-v1", len = 32B)`.
- Chunk size default 512 KiB. For each chunk:
  - `iv`: 96-bit random
  - `aad`: `{fileId, chunkIndex, totalChunks, aid, bid}`
  - `ciphertext, tag = AES-256-GCM(k_file_xfer, iv, chunkBytes, aad)`
- Server stores `{fileId, chunkIndex, iv, tag, ciphertext, metadata}` only.
- Receiver downloads chunks, verifies tag/aad, reassembles.

## Authentication & Key Storage
- Register: username + password → bcrypt/argon2 hash stored server-side; `idPub` stored with user profile.
- Login: password check; returns session token/JWT. Private key remains local in IndexedDB encrypted with password-derived AES-GCM key.
- Optional 2FA: TOTP secret stored server-side encrypted; verification on login.

## Logging (server-side)
- `auth.success` / `auth.fail`
- `handshake.init`, `handshake.resp`, `handshake.confirm`, `handshake.reject` (bad sig/nonce/ts/seq)
- `decrypt.fail`, `replay.detected`, `signature.invalid`
- `metadata.access` (message/file fetch)

## MITM Demonstration Plan
1) Vulnerable mode (for demo only): disable signature verification in handshake; run attacker relay that swaps ephemeral keys. Show A/B derive attacker-shared keys and attacker decrypts messages.
2) Secure mode: signatures + confirmations enabled. Same attacker script fails to validate and handshake is aborted/logged.

## Replay Demonstration Plan
- Record a valid `INIT` + message; replay after seq or timestamp window. Server/client rejects with `replay.detected` log and message is not decrypted.

## Deployment Notes
- Always serve over HTTPS/WSS.
- CSP to restrict origins; disable third-party scripts.
- Use HTTP-only, secure cookies for session tokens; short TTL.
