const express = require('express');
const router = express.Router();
const MITMAttacker = require('../../attack-scripts/mitm-attacker');
const { logSecurityEvent } = require('../utils/audit');

// Demonstrate MITM attack
router.post('/demonstrate', async (req, res) => {
  try {
    console.log('\n=== MITM Attack Demonstration Requested ===\n');
    
    const attacker = new MITMAttacker();
    const result = attacker.demonstrateAttack();
    
    // Log the attack demonstration
    await logSecurityEvent({
      eventType: 'MITM_DEMO',
      severity: 'INFO',
      description: 'MITM attack demonstration executed',
      details: {
        attackSuccess: result.success,
        messagesIntercepted: result.interceptedMessages.length
      }
    });
    
    res.json({
      success: true,
      demonstration: {
        vulnerable: result,
        attackLogs: attacker.getAttackLogs()
      }
    });
  } catch (error) {
    console.error('MITM demonstration error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Show signature protection
router.get('/signature-protection', (req, res) => {
  try {
    const attacker = new MITMAttacker();
    attacker.demonstrateSignatureProtection();
    
    res.json({
      success: true,
      message: 'Signature protection prevents MITM attacks',
      details: {
        vulnerableExchange: 'Attacker can intercept and modify DH public keys',
        signedExchange: 'Digital signatures authenticate the sender',
        protection: 'Bob verifies Alice\'s signature before accepting her DH public key'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;