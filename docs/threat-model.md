# STRIDE Threat Model

## Scope
- Clients (React app, Web Crypto, IndexedDB key storage)
- Network (HTTPS/WebSocket transport, relay of ciphertext/handshake)
- Server (Express API, MongoDB metadata/logs)
- Crypto materials (identity keys, session keys, file keys)

## Assets
- Confidentiality of messages/files
- Integrity/authenticity of handshakes and messages
- Availability of messaging/file services
- User credentials and identity keys

## Threats & Mitigations (by STRIDE)
- **Spoofing**
  - Attack: MITM swaps ECDH keys; forged user sessions.  
  - Mitigations: Signed handshake (ECDSA over identity keys), key-confirmation MAC, bcrypt/argon2 auth, HTTPS, optional TOTP.
- **Tampering**
  - Attack: Modify ciphertext or metadata.  
  - Mitigations: AES-GCM tags with AAD (metadata), signature checks, sequence validation, server logs tamper attempts.
- **Repudiation**
  - Attack: Deny sending messages.  
  - Mitigations: Server logs auth/handshake/message metadata; signatures on handshake; timestamps + seq for ordering (note: E2EE limits strong non-repudiation—documented residual risk).
- **Information Disclosure**
  - Attack: Server compromise, database leak, side-loading plaintext.  
  - Mitigations: No plaintext or private keys server-side; ciphertext-only storage; PBKDF2+AES-GCM for local key encryption; HTTPS; minimal metadata retention; encryption for TOTP secrets.
- **Denial of Service**
  - Attack: Replay floods, handshake spam, oversized payloads, storage exhaustion.  
  - Mitigations: Rate limiting, nonce/seq/timestamp replay rejection, size caps on uploads/chunks, auth required for metadata access, log + alert abnormal rates.
- **Elevation of Privilege**
  - Attack: Bypass auth, inject server code, escalate via malformed payloads.  
  - Mitigations: Input validation, JWT/session checks on every route, least-privileged DB roles, CSP, static typing/validation for payloads, dependency scanning (npm audit).

## Residual Risks / Notes
- Client compromise (malware/browser extensions) can steal decrypted data—outside project scope.
- Metadata leakage (who-talks-to-who, timing) persists; mitigate via padding/batching (future work).
- Clock dependence for timestamps; require NTP-sync and allow small skew window.
