// MITM Attack Demonstration Script
// This script intercepts and manipulates the vulnerable DH key exchange

const VulnerableDHKeyExchange = require('./vulnerable-dh');
const crypto = require('crypto');

class MITMAttacker {
  constructor() {
    this.aliceDH = null;
    this.bobDH = null;
    this.sessionKeyAlice = null;
    this.sessionKeyBob = null;
    this.interceptedMessages = [];
  }

  // Simulate the attack scenario
  demonstrateAttack() {
    console.log('\n=== MITM ATTACK DEMONSTRATION ===\n');
    
    // Step 1: Normal key exchange (vulnerable)
    console.log('1. Alice and Bob attempt key exchange (NO SIGNATURES)...\n');
    
    const alice = new VulnerableDHKeyExchange();
    const bob = new VulnerableDHKeyExchange();
    
    // Alice generates her keys
    const alicePublicKey = alice.generateKeys();
    console.log('Alice generates public key:', alicePublicKey.toString('hex').substring(0, 32) + '...');
    
    // Bob generates his keys
    const bobPublicKey = bob.generateKeys();
    console.log('Bob generates public key:', bobPublicKey.toString('hex').substring(0, 32) + '...\n');
    
    // Step 2: ATTACKER INTERCEPTS!
    console.log('2. 🚨 ATTACKER INTERCEPTS THE EXCHANGE! 🚨\n');
    
    // Attacker creates two separate DH exchanges
    this.aliceDH = new VulnerableDHKeyExchange();
    this.bobDH = new VulnerableDHKeyExchange();
    
    const attackerPublicForAlice = this.aliceDH.generateKeys();
    const attackerPublicForBob = this.bobDH.generateKeys();
    
    console.log('Attacker generates fake public key for Alice:', attackerPublicForAlice.toString('hex').substring(0, 32) + '...');
    console.log('Attacker generates fake public key for Bob:', attackerPublicForBob.toString('hex').substring(0, 32) + '...\n');
    
    // Step 3: Attacker completes the exchanges
    console.log('3. Attacker completes separate key exchanges:\n');
    
    // Alice thinks she's exchanging with Bob, but it's the attacker
    alice.computeSharedSecret(attackerPublicForAlice);
    this.aliceDH.computeSharedSecret(alicePublicKey);
    this.sessionKeyAlice = this.aliceDH.deriveSessionKey();
    
    console.log('✓ Attacker establishes session with Alice');
    console.log('  Session Key (Attacker-Alice):', this.sessionKeyAlice.toString('hex').substring(0, 32) + '...\n');
    
    // Bob thinks he's exchanging with Alice, but it's the attacker
    bob.computeSharedSecret(attackerPublicForBob);
    this.bobDH.computeSharedSecret(bobPublicKey);
    this.sessionKeyBob = this.bobDH.deriveSessionKey();
    
    console.log('✓ Attacker establishes session with Bob');
    console.log('  Session Key (Attacker-Bob):', this.sessionKeyBob.toString('hex').substring(0, 32) + '...\n');
    
    // Step 4: Demonstrate message interception
    console.log('4. Message Interception:\n');
    
    const aliceMessage = 'Hey Bob, let\'s meet at 3 PM. The password is: SECRET123';
    console.log('Alice sends message:', aliceMessage);
    
    // Encrypt with Alice's session key
    const encryptedForAttacker = this.encryptMessage(aliceMessage, this.sessionKeyAlice);
    console.log('Encrypted (Alice → Attacker):', encryptedForAttacker.ciphertext.substring(0, 32) + '...\n');
    
    // Attacker decrypts
    const decrypted = this.decryptMessage(encryptedForAttacker, this.sessionKeyAlice);
    console.log('🔓 ATTACKER DECRYPTS:', decrypted);
    
    // Attacker can modify the message
    const modifiedMessage = 'Hey Bob, let\'s meet at 5 PM. The password is: HACKED456';
    console.log('🔧 ATTACKER MODIFIES TO:', modifiedMessage + '\n');
    
    // Re-encrypt with Bob's session key
    const encryptedForBob = this.encryptMessage(modifiedMessage, this.sessionKeyBob);
    console.log('Encrypted (Attacker → Bob):', encryptedForBob.ciphertext.substring(0, 32) + '...');
    
    // Bob receives and decrypts
    const bobReceives = this.decryptMessage(encryptedForBob, this.sessionKeyBob);
    console.log('Bob receives:', bobReceives + '\n');
    
    console.log('=== ATTACK SUCCESSFUL ===');
    console.log('Bob receives a modified message without knowing it was intercepted!\n');
    
    // Log the attack
    this.interceptedMessages.push({
      timestamp: new Date(),
      original: aliceMessage,
      modified: modifiedMessage,
      sender: 'Alice',
      receiver: 'Bob'
    });
    
    return {
      success: true,
      originalMessage: aliceMessage,
      modifiedMessage: modifiedMessage,
      interceptedMessages: this.interceptedMessages
    };
  }

  // Demonstrate how signatures prevent MITM
  demonstrateSignatureProtection() {
    console.log('\n=== SIGNATURE PROTECTION DEMONSTRATION ===\n');
    
    console.log('1. Alice generates DH public key and SIGNS it with her private key');
    console.log('2. Bob verifies Alice\'s signature using her public RSA/ECC key');
    console.log('3. If signature is valid, Bob knows the DH public key came from Alice\n');
    
    console.log('Attempting MITM attack with signatures:\n');
    
    console.log('❌ Attacker cannot sign with Alice\'s private key');
    console.log('❌ Bob detects invalid signature and REJECTS the exchange');
    console.log('❌ MITM attack FAILS!\n');
    
    console.log('=== SIGNATURES PREVENT MITM ===\n');
  }

  // Helper: Encrypt message with AES-256-GCM
  encryptMessage(plaintext, sessionKey) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
    
    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return {
      ciphertext,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  // Helper: Decrypt message with AES-256-GCM
  decryptMessage(encrypted, sessionKey) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      sessionKey,
      Buffer.from(encrypted.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
    
    let plaintext = decipher.update(encrypted.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
    
    return plaintext;
  }

  // Get attack logs
  getAttackLogs() {
    return this.interceptedMessages;
  }
}

// Run the demonstration
if (require.main === module) {
  const attacker = new MITMAttacker();
  attacker.demonstrateAttack();
  attacker.demonstrateSignatureProtection();
}

module.exports = MITMAttacker;