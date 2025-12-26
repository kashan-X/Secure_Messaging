# Attack Demonstrations

## MITM (Unsigned DH) vs Signed Handshake
1. Start backend (`npm run dev` in `backend`) and frontend (`npm run dev` in `frontend`).
2. With two browser sessions (User A + User B), perform a normal signed handshake (INIT → RESP → CONFIRM). It succeeds and a session becomes `ACTIVE`.
3. MITM attempt: intercept `INIT` in a proxy (Burp/Wireshark) and replace `A_eph_pub` with an attacker key and recompute `nonceA/tsA`. Because the digital signature covers `A_eph_pub|nonceA|tsA|seqA|alg|bid`, verification in `handleInit` fails and the handshake is dropped. Server logs show `handshake error: invalid signature` and no session is created.
4. (Optional vulnerable demo) Comment out `verifySignature` checks in `frontend/src/crypto/handshake.js` to simulate “unsigned DH”. The attacker can now swap keys, derive a shared secret with each side, and decrypt messages—demonstrating why the signed variant is necessary.

## Replay Attack
1. Send an encrypted message once (seq N).
2. Re-send the identical POST `/api/messages` payload (using `curl`/Burp “repeater”). Server detects duplicate `(sender, receiver, seq)` and returns HTTP 409 with log event `replay.detected`.
3. If an attacker changes `seq` but replays old ciphertext, the client rejects during decrypt because `recordInboundSeq` enforces monotonic sequences and the AES-GCM tag is bound to AAD (metadata with `seq/ts`). The message is never shown.

## Logging/Forensics to Capture Attacks
- Replay detections, invalid signatures, and metadata fetches are persisted in `logs` collection via `audit()` in `backend/src/utils/audit.js`.
- Collect evidence by tailing the logs collection (`db.logs.find().sort({createdAt:-1})`) while running the above experiments.
