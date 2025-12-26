# MITM Attack Demonstration Scripts

## Overview
These scripts demonstrate Man-in-the-Middle (MITM) attacks on vulnerable key exchange protocols and show how digital signatures prevent such attacks.

## Files

### 1. vulnerable-dh.js
Implements a Diffie-Hellman key exchange **without** digital signatures.
This is intentionally vulnerable to MITM attacks.

### 2. mitm-attacker.js
The main attack script that:
- Intercepts DH public keys
- Establishes separate sessions with both parties
- Decrypts, reads, and modifies messages
- Demonstrates why signatures are essential

### 3. proxy-server.js (Optional)
A simple proxy server to intercept HTTP traffic.

## Running the Demonstration

### Command Line Demo
```bash
cd attack-scripts
node mitm-attacker.js
```

### Web Interface Demo
1. Start your backend server
2. Navigate to `/mitm-demo` in your frontend
3. Click "Run MITM Attack"

## Attack Scenarios

### Scenario 1: Vulnerable Exchange
```
Alice --[DH Public A]--> Attacker --[DH Public X]--> Bob
Alice <--[DH Public X]-- Attacker <--[DH Public B]-- Bob

Result: Attacker can decrypt all messages
```

### Scenario 2: Secure Exchange (With Signatures)
```
Alice --[DH Public A + Signature]--> Bob
Bob verifies signature with Alice's public key
Result: MITM attack fails due to signature verification
```

## Security Analysis

### Why Vulnerable?
- No authentication of DH public keys
- Attacker can replace keys without detection
- Both parties unknowingly communicate with attacker

### How Signatures Help
- Alice signs her DH public key with her RSA/ECC private key
- Bob verifies the signature using Alice's public key
- Attacker cannot forge the signature (needs Alice's private key)
- Any tampering is detected and rejected

## Report Documentation

Include in your report:
1. Attack flow diagrams
2. Console output screenshots
3. Wireshark packet captures (if applicable)
4. Explanation of why DH alone is insufficient
5. How your final system prevents MITM attacks

## Testing Checklist
- [ ] Vulnerable DH exchange works
- [ ] Attacker successfully intercepts messages
- [ ] Attacker can modify messages
- [ ] Signature-based exchange rejects tampering
- [ ] Logs are generated for all events
- [ ] Screenshots captured for report
## Step 9: Running Everything

### Start Backend
```bash
cd backend
npm install
npm start
```

### Start Frontend
```bash
cd frontend
npm install
npm run dev
```

### Run CLI Demo
```bash
cd attack-scripts
node mitm-attacker.js
```

---

## Step 10: For Your Report

### Screenshots to Capture:
1. Console output showing successful MITM attack
2. Original vs Modified message comparison
3. Web interface showing attack demonstration
4. Signature verification failure when MITM attempted
5. Audit logs showing attack detection

### Diagrams to Include:
1. Vulnerable DH exchange flow
2. MITM attack sequence diagram
3. Secure exchange with signatures
4. Comparison table

### Code Snippets:
- Key sections of vulnerable-dh.js
- Attack logic from mitm-attacker.js
- Signature verification from your secure handshake

---

## Key Points for Evaluation

✅ **Attack Demonstration (15 marks)**
- Working MITM attack script
- Clear demonstration of vulnerability
- Proof that signatures prevent the attack

✅ **Documentation**
- Attack flow explained
- Screenshots and logs
- Security analysis

✅ **Originality**
- Your own implementation
- Not copied from external libraries
- Clear understanding demonstrated