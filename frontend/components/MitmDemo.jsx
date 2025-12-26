import { useState } from 'react';
import axios from 'axios';
import './MitmDemo.css';
import { AlertTriangle, Shield, Lock, Key, Bug, Check, X, RefreshCw, Copy } from 'lucide-react';

export default function MitmDemo() {
  const [loading, setLoading] = useState(false);
  const [attackResult, setAttackResult] = useState(null);
  const [activeTab, setActiveTab] = useState('vulnerable');
  const [logs, setLogs] = useState([]);
  const [signatureResult, setSignatureResult] = useState(null);

  const addLog = (message, type = 'info') => {
    const icon = {
      info: 'ℹ️',
      success: '✅',
      error: '❌',
      warning: '⚠️'
    }[type];

    setLogs(prev => [{
      id: Date.now(),
      message: `${icon} ${message}`,
      type,
      timestamp: new Date().toLocaleTimeString()
    }, ...prev.slice(0, 10)]);
  };

  const runMitmDemo = async () => {
    setLoading(true);
    setAttackResult(null);
    setLogs([]);

    addLog('Starting MITM attack simulation...', 'info');
    addLog('Setting up vulnerable Diffie-Hellman key exchange...', 'info');

    try {
      // Simulate MITM attack steps
      addLog('Step 1: Alice generates DH public key (g^a mod p)', 'info');
      await new Promise(resolve => setTimeout(resolve, 500));

      addLog('Step 2: Mallory (attacker) intercepts communication', 'warning');
      await new Promise(resolve => setTimeout(resolve, 500));

      addLog('Step 3: Mallory replaces Alice\'s public key with her own', 'danger');
      await new Promise(resolve => setTimeout(resolve, 500));

      addLog('Step 4: Bob receives attacker\'s key, thinking it\'s from Alice', 'danger');
      await new Promise(resolve => setTimeout(resolve, 500));

      addLog('Step 5: Mallory establishes separate sessions with both parties', 'danger');
      await new Promise(resolve => setTimeout(resolve, 500));

      // Simulated attack result
      const simulatedResult = {
        vulnerable: {
          originalMessage: "Hello Bob, transfer $1000 to account X.",
          modifiedMessage: "Hello Bob, transfer $5000 to account M (Mallory's account).",
          aliceMalloryKey: "0x8f3a1c4d...",
          malloryBobKey: "0x5b2c9e7f...",
          attackSuccessful: true
        },
        attackLogs: [
          {
            timestamp: new Date().toISOString(),
            sender: "Alice",
            receiver: "Bob",
            original: "Hello Bob, transfer $1000 to account X.",
            modified: "Hello Bob, transfer $5000 to account M (Mallory's account)."
          }
        ]
      };

      setAttackResult(simulatedResult);
      addLog('MITM Attack Successful! All communications are compromised.', 'error');
      addLog('Alice-Mallory session key: 0x8f3a1c4d...', 'detail');
      addLog('Mallory-Bob session key: 0x5b2c9e7f...', 'detail');

    } catch (error) {
      console.error('Demo error:', error);
      addLog('Failed to run MITM demonstration: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const showSignatureProtection = async () => {
    addLog('Testing MITM protection with digital signatures...', 'info');
    addLog('Step 1: Alice signs her DH public key with RSA private key', 'info');

    try {
      await new Promise(resolve => setTimeout(resolve, 500));
      addLog('Step 2: Mallory attempts to intercept and forge signature', 'warning');
      await new Promise(resolve => setTimeout(resolve, 500));
      addLog('Step 3: Bob verifies signature with Alice\'s public RSA key', 'info');
      await new Promise(resolve => setTimeout(resolve, 500));
      addLog('Step 4: SIGNATURE VERIFICATION FAILED!', 'success');
      addLog('Step 5: Key exchange rejected - MITM attack prevented!', 'success');

      setSignatureResult({
        protected: true,
        message: "Digital signature verification prevented MITM attack",
        details: "Signature validation failed due to key mismatch"
      });

    } catch (error) {
      console.error('Protection demo error:', error);
      addLog('Error in protection demo: ' + error.message, 'error');
    }
  };

  const runSimulatedNetworkAttack = async () => {
    addLog('Simulating network-level MITM attack...', 'info');
    addLog('Starting MITM proxy on port 8080...', 'info');

    try {
      const response = await axios.post('http://localhost:5000/api/attack/mitm/simulate', {
        simulateNetwork: true,
        port: 8080
      });

      addLog('MITM proxy started successfully', 'success');
      addLog(`Proxy listening on port ${response.data.proxyPort || 8080}`, 'info');
      addLog('All traffic can now be intercepted', 'warning');

    } catch (error) {
      addLog('Network simulation error: ' + (error.response?.data?.error || error.message), 'error');
    }
  };

  const clearLogs = () => {
    setLogs([]);
    setAttackResult(null);
    setSignatureResult(null);
  };

  return (
    <div className="mitm-demo">
      <div className="mitm-header">
        <div className="header-content">
          <div className="header-title">
            <Bug size={32} className="header-icon" />
            <div>
              <h2>MITM Attack Demonstration</h2>
              <p className="muted">Showcasing vulnerability and protection mechanisms</p>
            </div>
          </div>
          <div className="header-badges">
            <span className="badge vulnerable">Vulnerable</span>
            <span className="badge protected">Protected</span>
          </div>
        </div>
      </div>

      <div className="mitm-content">
        {/* Control Panel */}
        <div className="control-panel">
          <div className="panel-header">
            <Shield size={20} />
            <h3>Attack Simulation Controls</h3>
          </div>

          <div className="control-buttons">
            <button
              className={`btn ${activeTab === 'vulnerable' ? 'btn-danger' : 'btn-secondary'}`}
              onClick={runMitmDemo}
              disabled={loading}
            >
              {loading ? (
                <>
                  <RefreshCw size={16} className="spinning" />
                  Running Attack...
                </>
              ) : (
                <>
                  <Bug size={16} />
                  Run MITM Attack (Vulnerable DH)
                </>
              )}
            </button>

            <button
              className="btn btn-success"
              onClick={showSignatureProtection}
              disabled={loading}
            >
              <Shield size={16} />
              Show Signature Protection
            </button>

            <button
              className="btn btn-warning"
              onClick={runSimulatedNetworkAttack}
            >
              <AlertTriangle size={16} />
              Simulate Network Attack
            </button>

            <button
              className="btn btn-ghost"
              onClick={clearLogs}
            >
              Clear Logs
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="mitm-tabs">
          <div className="tab-buttons">
            <button
              className={`tab-btn ${activeTab === 'vulnerable' ? 'active' : ''}`}
              onClick={() => setActiveTab('vulnerable')}
            >
              <X size={18} />
              Vulnerable Exchange
            </button>
            <button
              className={`tab-btn ${activeTab === 'secure' ? 'active' : ''}`}
              onClick={() => setActiveTab('secure')}
            >
              <Check size={18} />
              Secure Exchange
            </button>
          </div>

          <div className="tab-content">
            {/* Vulnerable Exchange Tab */}
            {activeTab === 'vulnerable' && (
              <div className="tab-panel vulnerable-tab">
                <div className="tab-header">
                  <X size={24} className="tab-icon error" />
                  <div>
                    <h3>❌ Vulnerable DH Key Exchange (Without Signatures)</h3>
                    <p className="muted">Demonstrates how MITM attacks succeed without authentication</p>
                  </div>
                </div>

                <div className="attack-flow">
                  <h4>Attack Flow:</h4>
                  <div className="flow-steps">
                    <div className="step">
                      <div className="step-number">1</div>
                      <div className="step-content">
                        <strong>Alice generates DH public key (g^a mod p)</strong>
                        <p className="tiny muted">Alice creates her part of the key exchange</p>
                      </div>
                    </div>

                    <div className="step attack-step">
                      <div className="step-number">2</div>
                      <div className="step-content">
                        <strong>🚨 Attacker intercepts and replaces with their own public key (g^x mod p)</strong>
                        <p className="tiny muted">Mallory replaces Alice's public key</p>
                      </div>
                    </div>

                    <div className="step">
                      <div className="step-number">3</div>
                      <div className="step-content">
                        <strong>Bob receives attacker's public key, thinking it's from Alice</strong>
                        <p className="tiny muted">Bob is unaware of the attack</p>
                      </div>
                    </div>

                    <div className="step">
                      <div className="step-number">4</div>
                      <div className="step-content">
                        <strong>Bob generates his DH public key (g^b mod p)</strong>
                        <p className="tiny muted">Bob responds with his public key</p>
                      </div>
                    </div>

                    <div className="step attack-step">
                      <div className="step-number">5</div>
                      <div className="step-content">
                        <strong>🚨 Attacker intercepts and replaces with their own public key (g^y mod p)</strong>
                        <p className="tiny muted">Mallory intercepts Bob's response</p>
                      </div>
                    </div>

                    <div className="step">
                      <div className="step-number">6</div>
                      <div className="step-content">
                        <strong>Attacker now has two session keys: one with Alice, one with Bob</strong>
                        <p className="tiny muted">Mallory can decrypt all communications</p>
                      </div>
                    </div>

                    <div className="step attack-step">
                      <div className="step-number">7</div>
                      <div className="step-content">
                        <strong>Attacker can decrypt, read, and modify all messages</strong>
                        <p className="tiny muted">Complete compromise of communication</p>
                      </div>
                    </div>
                  </div>
                </div>

                {attackResult && (
                  <div className="attack-results">
                    <h4>Attack Results:</h4>
                    <div className="result-card error">
                      <div className="result-header">
                        <AlertTriangle size={20} />
                        <h5>MITM Attack Successful</h5>
                      </div>
                      <div className="result-details">
                        <div className="detail-row">
                          <span className="detail-label">Original Message:</span>
                          <span className="detail-value">{attackResult.vulnerable.originalMessage}</span>
                        </div>
                        <div className="detail-row">
                          <span className="detail-label">Modified Message:</span>
                          <span className="detail-value">{attackResult.vulnerable.modifiedMessage}</span>
                        </div>
                        <div className="detail-row">
                          <span className="detail-label">Alice-Attacker Key:</span>
                          <code className="key-value">{attackResult.vulnerable.aliceMalloryKey}</code>
                        </div>
                        <div className="detail-row">
                          <span className="detail-label">Attacker-Bob Key:</span>
                          <code className="key-value">{attackResult.vulnerable.malloryBobKey}</code>
                        </div>
                      </div>
                      <div className="result-conclusion error">
                        <X size={16} />
                        <span>Attack Successful - All communications are compromised!</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Secure Exchange Tab */}
            {activeTab === 'secure' && (
              <div className="tab-panel secure-tab">
                <div className="tab-header">
                  <Check size={24} className="tab-icon success" />
                  <div>
                    <h3>✅ Secure DH Key Exchange (With Digital Signatures)</h3>
                    <p className="muted">Demonstrates how digital signatures prevent MITM attacks</p>
                  </div>
                </div>

                <div className="protection-flow">
                  <h4>Protection Flow:</h4>
                  <div className="flow-steps">
                    <div className="step protected-step">
                      <div className="step-number">1</div>
                      <div className="step-content">
                        <strong>Alice generates DH public key (g^a mod p)</strong>
                        <p className="tiny muted">Alice creates her part of the key exchange</p>
                      </div>
                    </div>

                    <div className="step protected-step">
                      <div className="step-number">2</div>
                      <div className="step-content">
                        <strong>Alice signs her DH public key with her RSA/ECC private key</strong>
                        <p className="tiny muted">Digital signature provides authentication</p>
                      </div>
                    </div>

                    <div className="step protected-step">
                      <div className="step-number">3</div>
                      <div className="step-content">
                        <strong>Alice sends: {'{'}DHpublic, Signature{'}'}</strong>
                        <p className="tiny muted">Signed key exchange message</p>
                      </div>
                    </div>
                    <div className="step protected-step">
                      <div className="step-number">4</div>
                      <div className="step-content">
                        <strong>Bob receives the message</strong>
                        <p className="tiny muted">Bob receives the signed key</p>
                      </div>
                    </div>

                    <div className="step protected-step">
                      <div className="step-number">5</div>
                      <div className="step-content">
                        <strong>Bob verifies the signature using Alice's public RSA/ECC key</strong>
                        <p className="tiny muted">Signature verification process</p>
                      </div>
                    </div>

                    <div className="step">
                      <div className="step-number">6</div>
                      <div className="step-content">
                        <strong>If signature is valid ✓, Bob accepts the DH public key</strong>
                        <p className="tiny muted">Secure key exchange established</p>
                      </div>
                    </div>

                    <div className="step">
                      <div className="step-number">7</div>
                      <div className="step-content">
                        <strong>If signature is invalid ❌, Bob rejects the exchange</strong>
                        <p className="tiny muted">Attack detected and prevented</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="protection-explanation">
                  <h4>Why This Prevents MITM:</h4>
                  <div className="protection-points">
                    <div className="protection-point">
                      <Lock size={20} className="point-icon" />
                      <div>
                        <strong>🔒 Attacker cannot forge Alice's digital signature</strong>
                        <p className="tiny muted">Digital signatures require the private key</p>
                      </div>
                    </div>

                    <div className="protection-point">
                      <Shield size={20} className="point-icon" />
                      <div>
                        <strong>🔒 If attacker tries to replace the DH public key, signature verification fails</strong>
                        <p className="tiny muted">Signature validation detects tampering</p>
                      </div>
                    </div>

                    <div className="protection-point">
                      <AlertTriangle size={20} className="point-icon" />
                      <div>
                        <strong>🔒 Bob will detect the attack and refuse to continue</strong>
                        <p className="tiny muted">Attack is detected and blocked</p>
                      </div>
                    </div>

                    <div className="protection-point">
                      <Key size={20} className="point-icon" />
                      <div>
                        <strong>🔒 Message integrity and sender authentication are guaranteed</strong>
                        <p className="tiny muted">Both parties can verify each other's identity</p>
                      </div>
                    </div>
                  </div>

                  {signatureResult && (
                    <div className="result-card success">
                      <div className="result-header">
                        <Check size={20} />
                        <h5>Signature Protection Active</h5>
                      </div>
                      <p className="result-message">{signatureResult.message}</p>
                      <p className="tiny muted">{signatureResult.details}</p>
                      <div className="result-conclusion success">
                        <Check size={16} />
                        <span>MITM Attack Prevented - Digital signatures protect the key exchange!</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Attack Logs */}
        <div className="logs-panel">
          <div className="panel-header">
            <RefreshCw size={20} />
            <h3>Attack Simulation Logs</h3>
            <span className="badge">{logs.length} events</span>
          </div>

          <div className="logs-container">
            {logs.length === 0 ? (
              <div className="empty-logs">
                <p className="muted">Run a simulation to see attack logs</p>
              </div>
            ) : (
              <div className="logs-list">
                {logs.map(log => (
                  <div key={log.id} className={`log-entry ${log.type}`}>
                    <span className="timestamp">[{log.timestamp}]</span>
                    <span className="message">{log.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {logs.length > 0 && (
            <button
              className="btn btn-ghost clear-logs-btn"
              onClick={clearLogs}
            >
              Clear All Logs
            </button>
          )}
        </div>

        {/* Key Comparison */}
        <div className="comparison-panel">
          <div className="panel-header">
            <AlertTriangle size={20} />
            <h3>Security Comparison</h3>
          </div>

          <div className="comparison-table">
            <table>
              <thead>
                <tr>
                  <th>Aspect</th>
                  <th className="vulnerable">Vulnerable System</th>
                  <th className="protected">Our Secure System</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Authentication</td>
                  <td className="vulnerable">
                    <X size={16} />
                    <span>No authentication</span>
                  </td>
                  <td className="protected">
                    <Check size={16} />
                    <span>Digital Signatures</span>
                  </td>
                </tr>
                <tr>
                  <td>MITM Prevention</td>
                  <td className="vulnerable">
                    <X size={16} />
                    <span>Vulnerable</span>
                  </td>
                  <td className="protected">
                    <Check size={16} />
                    <span>Protected</span>
                  </td>
                </tr>
                <tr>
                  <td>Key Verification</td>
                  <td className="vulnerable">
                    <X size={16} />
                    <span>No verification</span>
                  </td>
                  <td className="protected">
                    <Check size={16} />
                    <span>Signature + Timestamp</span>
                  </td>
                </tr>
                <tr>
                  <td>Attack Detection</td>
                  <td className="vulnerable">
                    <X size={16} />
                    <span>Undetectable</span>
                  </td>
                  <td className="protected">
                    <Check size={16} />
                    <span>Logged & Alerted</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}