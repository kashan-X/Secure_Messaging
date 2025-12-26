import { useRef, useState } from 'react';
import './App.css';
import {
  clientAudit,
  fetchFileChunks,
  fetchInbox,
  fetchThread,
  initFileTransfer,
  loginUser,
  lookupUser,
  registerUser,
  sendMessage,
  uploadChunk,
} from './api';
import {
  decryptPrivateKey,
  encryptPrivateKey,
  generateIdentityKeyPair,
  loadIdentityRecord,
  saveIdentityKey,
} from './crypto/keys';
import {
  createInitHandshake,
  finalizeHandshake,
  handleConfirm,
  handleInit,
} from './crypto/handshake';
import { decryptChunk, decryptMessage, deriveFileKey, encryptChunk, encryptMessage } from './crypto/encryption';
import { canonicalJson } from './crypto/utils';
import { nextSeq, recordInboundSeq } from './crypto/replay';
import { Shield, Lock, Key, Upload, Download, MessageSquare, Users, File, LogOut, RefreshCw, Copy, Check, Bug, AlertTriangle } from 'lucide-react';
import MitmDemo from '../components/MitmDemo.jsx';

const HandshakeStatus = ({ sessions }) => (
  <div className="panel">
    <div className="panel-head">
      <div className="panel-title">
        <Key size={20} />
        <div>
          <p className="eyebrow">Secure Sessions</p>
          <h3>Active Channels</h3>
        </div>
      </div>
      <span className="pill alt">{Object.keys(sessions).length} active</span>
    </div>
    {Object.keys(sessions).length === 0 ? (
      <div className="empty-state">
        <Shield size={48} className="muted" />
        <p className="muted">No active sessions</p>
        <p className="tiny">Establish a secure channel by initiating a handshake</p>
      </div>
    ) : (
      <div className="session-grid">
        {Object.entries(sessions).map(([peerId, sess]) => (
          <div key={peerId} className={`session-card ${sess.status === 'active' ? 'active' : ''}`}>
            <div className="session-header">
              <div className="avatar">{peerId.slice(0, 2).toUpperCase()}</div>
              <span className="peer-id">{peerId.slice(0, 8)}...</span>
            </div>
            <div className="session-status">
              <span className={`status-dot ${sess.status}`}></span>
              <span className="status-text">{sess.status}</span>
            </div>
            <div className="session-info">
              <span className="tiny">AES-256-GCM</span>
              <span className="tiny">ECDH-P256</span>
            </div>
          </div>
        ))}
      </div>
    )}
  </div>
);

function App() {
  const [authForm, setAuthForm] = useState({ username: '', password: '' });
  const [user, setUser] = useState(null);
  const [identity, setIdentity] = useState({ privateKey: null, publicJwk: null });
  const [peerUsername, setPeerUsername] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [messages, setMessages] = useState([]);
  const [status, setStatus] = useState([]);
  const [sessionVersion, setSessionVersion] = useState(0);
  const [fileToSend, setFileToSend] = useState(null);
  const [downloadFileId, setDownloadFileId] = useState('');
  const [authStage, setAuthStage] = useState('choice');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('handshake');
  const [generatedFileIds, setGeneratedFileIds] = useState([]);
  const [copiedFileId, setCopiedFileId] = useState('');

  const sessionsRef = useRef({});
  const pendingInitsRef = useRef({});
  const processedHandshakeIds = useRef(new Set());
  const peerPublicCache = useRef({});

  const addStatus = (msg, type = 'info') => {
    const icon = {
      info: 'ℹ️',
      success: '✅',
      error: '❌',
      warning: '⚠️'
    }[type];
    setStatus((prev) => [`${icon} ${new Date().toLocaleTimeString()} — ${msg}`, ...prev].slice(0, 15));
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedFileId(text);
      addStatus(`File ID copied to clipboard: ${text.slice(0, 20)}...`, 'success');
      setTimeout(() => setCopiedFileId(''), 2000);
    } catch (err) {
      addStatus('Failed to copy to clipboard', 'error');
    }
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setDownloadFileId(text);
      addStatus('File ID pasted from clipboard', 'info');
    } catch (err) {
      addStatus('Failed to read from clipboard', 'error');
    }
  };

  const resetLocalKeys = async () => {
    try {
      await indexedDB.deleteDatabase('e2ee-keys');
      addStatus('Local key store reset successfully', 'success');
      addStatus('Please register again on this device', 'info');
    } catch (err) {
      addStatus(`Reset failed: ${err.message}`, 'error');
    }
  };

  const handleLogout = () => {
    setUser(null);
    setIdentity({ privateKey: null, publicJwk: null });
    sessionsRef.current = {};
    setGeneratedFileIds([]);
    addStatus('Logged out successfully', 'success');
  };

  const handleRegister = async () => {
    const username = authForm.username.trim();
    if (!username || !authForm.password) return addStatus('Please provide username and password', 'warning');

    setLoading(true);
    try {
      const { keyPair, publicJwk } = await generateIdentityKeyPair();
      const res = await registerUser({
        username,
        password: authForm.password,
        identityPublicKey: JSON.stringify(publicJwk),
      });
      const encryptedPriv = await encryptPrivateKey(keyPair.privateKey, authForm.password);
      await saveIdentityKey(res.id, encryptedPriv, publicJwk);
      addStatus(`Successfully registered ${username}`, 'success');
      addStatus('Keys generated and stored locally - Switch to Login', 'info');
      setAuthStage('login');
      setAuthForm({ username: '', password: '' });
    } catch (err) {
      addStatus(`Registration failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    const username = authForm.username.trim();
    if (!username || !authForm.password) return addStatus('Please provide username and password', 'warning');
    
    setLoading(true);
    try {
      const { token, user: loggedUser } = await loginUser({
        username,
        password: authForm.password,
      });
      const record = await loadIdentityRecord(loggedUser.id);
      if (!record) throw new Error('No local identity key found on this device. Register here first.');
      const privateKey = await decryptPrivateKey(record.encryptedPrivateKey, authForm.password);
      setUser(loggedUser);
      setIdentity({ privateKey, publicJwk: record.publicKeyJwk });
      addStatus(`Welcome back, ${username}!`, 'success');
      addStatus('Secure session established', 'info');
      setAuthForm({ username: '', password: '' });
    } catch (err) {
      addStatus(`Login failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const sendHandshakeEnvelope = async (receiverId, envelope, seqHint) => {
    const payloadB64 = btoa(JSON.stringify(envelope));
    await sendMessage({
      receiverId,
      ciphertext: payloadB64,
      iv: 'handshake',
      authTag: 'handshake',
      seq: seqHint || envelope.seqA || envelope.seqB || envelope.seqA2 || Date.now(),
      ts: Date.now(),
      type: 'handshake',
      metadata: { stage: envelope.stage },
    });
  };

  const initiateHandshake = async () => {
    if (!user || !identity.privateKey) return addStatus('Please login first', 'warning');
    if (!peerUsername) return addStatus('Enter peer username to initiate handshake', 'warning');
    
    setLoading(true);
    try {
      const peer = await lookupUser(peerUsername.trim());
      const peerPub = JSON.parse(peer.identityPublicKey);
      peerPublicCache.current[peer.id] = peerPub;

      const { envelope, state } = await createInitHandshake({
        self: { id: user.id },
        peer: { id: peer.id },
        identityPrivateKey: identity.privateKey,
        identityPublicJwk: identity.publicJwk,
      });
      pendingInitsRef.current[peer.id] = { ...state, peerPublicJwk: peerPub };
      await sendHandshakeEnvelope(peer.id, envelope, envelope.seqA);
      addStatus(`Handshake INIT sent to ${peer.username}`, 'success');
    } catch (err) {
      addStatus(`Handshake initiation failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const syncHandshakes = async () => {
    if (!user || !identity.privateKey) return addStatus('Please login first', 'warning');
    
    setLoading(true);
    try {
      const inbox = await fetchInbox('handshake');
      let processed = 0;

      for (const msg of inbox) {
        if (processedHandshakeIds.current.has(msg._id)) continue;
        processedHandshakeIds.current.add(msg._id);

        const envelope = JSON.parse(atob(msg.ciphertext));
        try {
          if (envelope.stage === 'init') {
            const { response, session } = await handleInit({
              envelope,
              self: user,
              identityPrivateKey: identity.privateKey,
              peerPublicJwk: envelope.A_id_pub,
            });
            sessionsRef.current[session.peerId] = session;
            setSessionVersion((v) => v + 1);
            await sendHandshakeEnvelope(envelope.aid, response, response.seqB);
            addStatus(`Responded to INIT from ${envelope.aid}`, 'success');
            processed++;
          } else if (envelope.stage === 'resp') {
            const initState = pendingInitsRef.current[envelope.bid];
            if (!initState) {
              addStatus('No pending init for response', 'warning');
              continue;
            }
            const { confirmMsg, session } = await finalizeHandshake({
              initState,
              responseEnvelope: envelope,
              peerPublicJwk: initState.peerPublicJwk,
            });
            sessionsRef.current[session.peerId] = session;
            setSessionVersion((v) => v + 1);
            await sendHandshakeEnvelope(envelope.bid, confirmMsg, confirmMsg.seqA2);
            addStatus(`Verified RESP and sent CONFIRM to ${envelope.bid}`, 'success');
            processed++;
          } else if (envelope.stage === 'confirm') {
            const session = sessionsRef.current[envelope.aid];
            if (!session) continue;
            const active = await handleConfirm({ session, confirmEnvelope: envelope });
            sessionsRef.current[envelope.aid] = active;
            setSessionVersion((v) => v + 1);
            addStatus(`Session ACTIVE with ${envelope.aid}`, 'success');
            processed++;
          }
        } catch (err) {
          addStatus(`Handshake error: ${err.message}`, 'error');
          await clientAudit('handshake.error', { stage: envelope.stage, reason: err.message });
        }
      }
      
      if (processed === 0) {
        addStatus('No new handshake messages to process', 'info');
      }
    } catch (err) {
      addStatus(`Sync failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const sendEncryptedMessage = async () => {
    if (!user || !identity.privateKey) return addStatus('Please login first', 'warning');
    if (!peerUsername || !plaintext) return addStatus('Peer username and message required', 'warning');
    
    setLoading(true);
    try {
      const peer = await lookupUser(peerUsername.trim());
      const session = sessionsRef.current[peer.id];
      if (!session || session.status !== 'active') return addStatus('No active session with peer', 'error');

      const seq = nextSeq(peer.id);
      const metadata = canonicalJson({ aid: user.id, bid: peer.id, ts: Date.now(), seq });
      const encrypted = await encryptMessage({
        key: session.kEnc,
        plaintext,
        aad: metadata,
      });
      await sendMessage({
        receiverId: peer.id,
        ciphertext: encrypted.ciphertextB64,
        iv: encrypted.ivB64,
        authTag: encrypted.authTagB64,
        aad: metadata,
        seq,
        ts: Date.now(),
        type: 'text',
      });
      addStatus(`Encrypted message sent to ${peer.username}`, 'success');
      setPlaintext('');
    } catch (err) {
      addStatus(`Failed to send message: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const loadThread = async () => {
    if (!user) return addStatus('Please login first', 'warning');
    if (!peerUsername) return addStatus('Enter peer username to load messages', 'warning');
    
    setLoading(true);
    try {
      const peer = await lookupUser(peerUsername.trim());
      const session = sessionsRef.current[peer.id];
      if (!session) return addStatus('No secure session established with peer', 'error');

      const thread = await fetchThread(peer.id);
      const decrypted = [];
      for (const msg of thread) {
        if (msg.type !== 'text') continue;
        try {
          if (msg.receiver === user.id) {
            recordInboundSeq(msg.sender, msg.seq);
          }
          const aad = msg.aad || canonicalJson({ aid: msg.sender, bid: msg.receiver, ts: msg.ts, seq: msg.seq });
          const plain = await decryptMessage({
            key: session.kEnc,
            ciphertextB64: msg.ciphertext,
            authTagB64: msg.authTag,
            ivB64: msg.iv,
            aad,
          });
          decrypted.push({
            id: msg._id,
            from: msg.sender === user.id ? 'me' : peer.username,
            text: plain,
            ts: new Date(msg.ts).toLocaleTimeString(),
          });
        } catch (err) {
          addStatus(`Decryption failed for message: ${err.message}`, 'error');
          await clientAudit('decrypt.fail', { messageId: msg._id, reason: err.message });
        }
      }
      setMessages(decrypted);
      addStatus(`Loaded ${decrypted.length} messages`, 'success');
    } catch (err) {
      addStatus(`Failed to load thread: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const sendFile = async () => {
    if (!user) return addStatus('Please login first', 'warning');
    if (!fileToSend) return addStatus('Choose a file to send', 'warning');
    if (!peerUsername) return addStatus('Enter peer username', 'warning');
    
    setLoading(true);
    try {
      const peer = await lookupUser(peerUsername.trim());
      const session = sessionsRef.current[peer.id];
      if (!session || session.status !== 'active') return addStatus('No active session for file transfer', 'error');

      // Generate file ID
      const fileId = crypto.randomUUID();
      
      // Store the file ID for display
      setGeneratedFileIds(prev => [{
        id: fileId,
        fileName: fileToSend.name,
        size: fileToSend.size,
        timestamp: new Date().toISOString(),
        peerUsername: peer.username
      }, ...prev.slice(0, 5)]); // Keep last 5 file IDs

      const chunkSize = 512 * 1024;
      const totalChunks = Math.ceil(fileToSend.size / chunkSize);
      const fileKey = await deriveFileKey(session.kFile, fileId);

      await initFileTransfer({
        fileId,
        receiverId: peer.id,
        totalChunks,
        fileName: fileToSend.name,
        fileSize: fileToSend.size,
        mimeType: fileToSend.type,
      });

      const buffer = await fileToSend.arrayBuffer();
      for (let idx = 0; idx < totalChunks; idx += 1) {
        const slice = buffer.slice(idx * chunkSize, Math.min(buffer.byteLength, (idx + 1) * chunkSize));
        const aad = canonicalJson({ fileId, chunkIndex: idx, totalChunks, aid: user.id, bid: peer.id });
        const enc = await encryptChunk({ key: fileKey, chunkBytes: slice, aad });
        await uploadChunk(fileId, {
          chunkIndex: idx,
          ciphertext: enc.ciphertextB64,
          iv: enc.ivB64,
          authTag: enc.authTagB64,
          aad,
          receiverId: peer.id,
        });
      }
      addStatus(`File "${fileToSend.name}" sent successfully! File ID: ${fileId}`, 'success');
      addStatus(`Share this File ID with the recipient: ${fileId}`, 'info');
      setFileToSend(null);
    } catch (err) {
      addStatus(`File upload failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const downloadFile = async () => {
    if (!user) return addStatus('Please login first', 'warning');
    if (!downloadFileId) return addStatus('Enter a file ID to download', 'warning');
    
    setLoading(true);
    try {
      const result = await fetchFileChunks(downloadFileId.trim());
      const meta = result.meta;
      const peerId = meta.sender === user.id ? meta.receiver : meta.sender;
      const session =
        sessionsRef.current[peerId] ||
        sessionsRef.current[String(peerId)] ||
        sessionsRef.current[String(meta.sender)] ||
        sessionsRef.current[String(meta.receiver)];
      if (!session) return addStatus(`No active session for file decryption`, 'error');

      const fileKey = await deriveFileKey(session.kFile, meta.fileId);
      const parts = [];
      for (const chunk of result.chunks) {
        const aad =
          chunk.aad ||
          canonicalJson({
            fileId: meta.fileId,
            chunkIndex: chunk.chunkIndex,
            totalChunks: meta.totalChunks,
            aid: chunk.sender,
            bid: chunk.receiver,
          });
        const bytes = await decryptChunk({
          key: fileKey,
          ciphertextB64: chunk.ciphertext,
          authTagB64: chunk.authTag,
          ivB64: chunk.iv,
          aad,
        });
        parts.push(bytes);
      }
      const totalLen = parts.reduce((sum, p) => sum + p.byteLength, 0);
      const merged = new Uint8Array(totalLen);
      let offset = 0;
      parts.forEach((p) => {
        merged.set(p, offset);
        offset += p.byteLength;
      });
      const blob = new Blob([merged], { type: meta.mimeType || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = meta.fileName || `download-${meta.fileId}`;
      link.click();
      URL.revokeObjectURL(url);
      addStatus(`Downloaded "${meta.fileName || meta.fileId}" successfully`, 'success');
      setDownloadFileId('');
    } catch (err) {
      addStatus(`Download failed: ${err.message}`, 'error');
      await clientAudit('decrypt.fail.file', { fileId: downloadFileId.trim(), reason: err.message });
    } finally {
      setLoading(false);
    }
  };

  // Main render
  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="brand">
            <Shield size={32} className="brand-icon" />
            <div>
              <h1>Secure Messenger</h1>
              <p className="muted">End-to-end encrypted communication</p>
            </div>
          </div>
          {user && (
            <div className="user-info">
              <div className="user-badge">
                <div className="avatar">{user.username.slice(0, 2).toUpperCase()}</div>
                <span>{user.username}</span>
              </div>
              <button className="btn-icon ghost" onClick={handleLogout} title="Logout">
                <LogOut size={20} />
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="main">
        {!user || !identity.privateKey ? (
          /* Authentication Section */
          <section className="auth-section">
            <div className="auth-card">
              <div className="auth-header">
                <Lock size={48} className="auth-icon" />
                <h2>Secure Authentication</h2>
                <p className="muted">All cryptographic operations happen locally in your browser</p>
              </div>

              {authStage === 'choice' ? (
                <div className="choice-grid">
                  <div className="choice-card" onClick={() => setAuthStage('register')}>
                    <div className="choice-icon">
                      <Key size={24} />
                    </div>
                    <h3>Create Account</h3>
                    <p className="muted small">Generate new cryptographic identity keys locally</p>
                    <button className="btn primary full-width">Register</button>
                    <ul className="feature-list">
                      <li>P-256 key pair generation</li>
                      <li>Local key storage (IndexedDB)</li>
                      <li>Password-encrypted private keys</li>
                    </ul>
                  </div>
                  <div className="choice-card" onClick={() => setAuthStage('login')}>
                    <div className="choice-icon">
                      <Lock size={24} />
                    </div>
                    <h3>Sign In</h3>
                    <p className="muted small">Use existing identity keys from this device</p>
                    <button className="btn ghost full-width">Login</button>
                    <ul className="feature-list">
                      <li>Password-based decryption</li>
                      <li>Local key retrieval</li>
                      <li>Session restoration</li>
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="auth-form-container">
                  <div className="auth-form-header">
                    <button className="btn-icon ghost" onClick={() => setAuthStage('choice')}>
                      ← Back
                    </button>
                    <h3>{authStage === 'register' ? 'Create New Account' : 'Sign In to Your Account'}</h3>
                  </div>
                  <div className="auth-form">
                    <div className="input-group">
                      <label>Username</label>
                      <input
                        placeholder="Enter your username"
                        value={authForm.username}
                        onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                        disabled={loading}
                      />
                    </div>
                    <div className="input-group">
                      <label>Password</label>
                      <input
                        type="password"
                        placeholder="Enter your password"
                        value={authForm.password}
                        onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                        disabled={loading}
                      />
                    </div>
                    <div className="auth-actions">
                      {authStage === 'register' ? (
                        <button 
                          className="btn primary full-width" 
                          onClick={handleRegister}
                          disabled={loading}
                        >
                          {loading ? 'Generating Keys...' : 'Register & Generate Keys'}
                        </button>
                      ) : (
                        <button 
                          className="btn primary full-width" 
                          onClick={handleLogin}
                          disabled={loading}
                        >
                          {loading ? 'Authenticating...' : 'Login'}
                        </button>
                      )}
                      <button className="btn text" onClick={resetLocalKeys} disabled={loading}>
                        Reset Local Key Store
                      </button>
                    </div>
                    <div className="security-note">
                      <Lock size={16} />
                      <p className="tiny">
                        Keys are encrypted with your password and stored locally in IndexedDB.
                        The server never sees your private keys.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </section>
        ) : (
          /* Main Application */
          <>
            {/* Navigation Tabs */}
            <nav className="tabs">
              <button 
                className={`tab ${activeTab === 'handshake' ? 'active' : ''}`}
                onClick={() => setActiveTab('handshake')}
              >
                <Key size={18} />
                Handshake
              </button>
              <button 
                className={`tab ${activeTab === 'messaging' ? 'active' : ''}`}
                onClick={() => setActiveTab('messaging')}
              >
                <MessageSquare size={18} />
                Messaging
              </button>
              <button 
                className={`tab ${activeTab === 'files' ? 'active' : ''}`}
                onClick={() => setActiveTab('files')}
              >
                <File size={18} />
                Files
              </button>
              <button 
                className={`tab ${activeTab === 'sessions' ? 'active' : ''}`}
                onClick={() => setActiveTab('sessions')}
              >
                <Users size={18} />
                Sessions
              </button>
              <button 
                className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
                onClick={() => setActiveTab('logs')}
              >
                <RefreshCw size={18} />
                Logs
              </button>
              {/* MITM Demo Tab */}
              <button 
                className={`tab ${activeTab === 'mitm' ? 'active' : ''}`}
                onClick={() => setActiveTab('mitm')}
              >
                <Bug size={18} />
                MITM Demo
              </button>
            </nav>

            {/* Tab Content */}
            <div className="tab-content">
              {activeTab === 'handshake' && (
                <div className="panel-grid">
                  <div className="panel">
                    <div className="panel-head">
                      <div className="panel-title">
                        <Key size={20} />
                        <div>
                          <p className="eyebrow">Handshake Protocol</p>
                          <h3>Establish Secure Session</h3>
                        </div>
                      </div>
                      <span className="pill alt">INIT → RESP → CONFIRM</span>
                    </div>
                    <div className="input-group">
                      <label>Peer Username</label>
                      <input
                        placeholder="Enter peer's username"
                        value={peerUsername}
                        onChange={(e) => setPeerUsername(e.target.value)}
                        disabled={loading}
                      />
                    </div>
                    <div className="button-group">
                      <button className="btn primary" onClick={initiateHandshake} disabled={loading}>
                        <Key size={18} />
                        Send INIT Handshake
                      </button>
                      <button className="btn ghost" onClick={syncHandshakes} disabled={loading}>
                        <RefreshCw size={18} />
                        Sync Handshakes
                      </button>
                    </div>
                    <div className="protocol-info">
                      <h4>Three-Way Handshake Protocol:</h4>
                      <ol className="protocol-steps">
                        <li><strong>INIT</strong> — Initiator sends ephemeral key and signature</li>
                        <li><strong>RESP</strong> — Responder verifies, computes shared secret, sends response</li>
                        <li><strong>CONFIRM</strong> — Initiator verifies, completes handshake</li>
                      </ol>
                    </div>
                  </div>

                  <HandshakeStatus key={sessionVersion} sessions={sessionsRef.current} />
                </div>
              )}

              {activeTab === 'messaging' && (
                <div className="panel-grid">
                  <div className="panel message-panel">
                    <div className="panel-head">
                      <div className="panel-title">
                        <MessageSquare size={20} />
                        <div>
                          <p className="eyebrow">Secure Messaging</p>
                          <h3>Encrypted Communication</h3>
                        </div>
                      </div>
                      <span className="pill alt">AES-GCM + Replay Protection</span>
                    </div>
                    
                    <div className="message-container">
                      <div className="message-input-area">
                        <div className="input-group">
                          <label>Peer Username</label>
                          <input
                            placeholder="Enter recipient username"
                            value={peerUsername}
                            onChange={(e) => setPeerUsername(e.target.value)}
                            disabled={loading}
                          />
                        </div>
                        <div className="input-group">
                          <label>Message</label>
                          <textarea
                            rows={3}
                            placeholder="Type your encrypted message here..."
                            value={plaintext}
                            onChange={(e) => setPlaintext(e.target.value)}
                            disabled={loading}
                          />
                        </div>
                        <div className="button-group">
                          <button className="btn primary" onClick={sendEncryptedMessage} disabled={loading}>
                            <Lock size={18} />
                            Send Encrypted Message
                          </button>
                          <button className="btn ghost" onClick={loadThread} disabled={loading}>
                            <RefreshCw size={18} />
                            Load Messages
                          </button>
                        </div>
                      </div>

                      <div className="message-thread">
                        <div className="thread-header">
                          <h4>Message History</h4>
                          <span className="pill">{messages.length} messages</span>
                        </div>
                        <div className="messages-list">
                          {messages.length === 0 ? (
                            <div className="empty-thread">
                              <MessageSquare size={48} className="muted" />
                              <p className="muted">No messages yet</p>
                              <p className="tiny">Send a message or load the conversation thread</p>
                            </div>
                          ) : (
                            messages.map((m) => (
                              <div key={m.id} className={`message-bubble ${m.from === 'me' ? 'sent' : 'received'}`}>
                                <div className="message-header">
                                  <span className="message-sender">{m.from}</span>
                                  <span className="message-time">{m.ts}</span>
                                </div>
                                <div className="message-content">{m.text}</div>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'files' && (
                <div className="panel-grid">
                  {/* Send File Panel */}
                  <div className="panel">
                    <div className="panel-head">
                      <div className="panel-title">
                        <Upload size={20} />
                        <div>
                          <p className="eyebrow">File Transfer</p>
                          <h3>Send Encrypted Files</h3>
                        </div>
                      </div>
                      <span className="pill alt">Chunked AES-GCM Encryption</span>
                    </div>
                    
                    <div className="input-group">
                      <label>Recipient Username</label>
                      <input
                        placeholder="Enter recipient username"
                        value={peerUsername}
                        onChange={(e) => setPeerUsername(e.target.value)}
                        disabled={loading}
                      />
                    </div>
                    
                    <div className="file-upload-area">
                      <label>File to Send</label>
                      <div className="file-dropzone">
                        <Upload size={32} className="muted" />
                        <p>{fileToSend ? fileToSend.name : 'Drag & drop or click to select file'}</p>
                        <p className="tiny muted">Max file size: 100MB</p>
                        <input
                          type="file"
                          onChange={(e) => setFileToSend(e.target.files?.[0] || null)}
                          disabled={loading}
                          className="file-input"
                        />
                      </div>
                      {fileToSend && (
                        <div className="file-info">
                          <span className="tiny">Size: {(fileToSend.size / 1024 / 1024).toFixed(2)} MB</span>
                          <span className="tiny">Type: {fileToSend.type || 'Unknown'}</span>
                        </div>
                      )}
                    </div>
                    
                    <button className="btn primary full-width" onClick={sendFile} disabled={loading}>
                      <Upload size={18} />
                      Encrypt & Upload File
                    </button>

                    {/* Recent File IDs Section */}
                    {generatedFileIds.length > 0 && (
                      <div className="recent-files">
                        <h4>Recent File Transfers</h4>
                        <p className="tiny muted">Share these File IDs with recipients</p>
                        <div className="file-ids-list">
                          {generatedFileIds.map((file, index) => (
                            <div key={index} className="file-id-card">
                              <div className="file-id-header">
                                <span className="file-name">{file.fileName}</span>
                                <span className="file-size">({(file.size / 1024 / 1024).toFixed(2)} MB)</span>
                              </div>
                              <div className="file-id-content">
                                <div className="file-id-display">
                                  <code className="file-id" title={file.id}>
                                    {file.id.slice(0, 24)}...
                                  </code>
                                  <button 
                                    className="btn-icon copy-btn" 
                                    onClick={() => copyToClipboard(file.id)}
                                    title="Copy File ID"
                                  >
                                    {copiedFileId === file.id ? <Check size={16} /> : <Copy size={16} />}
                                  </button>
                                </div>
                                <div className="file-id-meta">
                                  <span className="tiny muted">To: {file.peerUsername}</span>
                                  <span className="tiny muted">
                                    {new Date(file.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                  </span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Receive File Panel */}
                  <div className="panel">
                    <div className="panel-head">
                      <div className="panel-title">
                        <Download size={20} />
                        <div>
                          <p className="eyebrow">File Download</p>
                          <h3>Retrieve & Decrypt</h3>
                        </div>
                      </div>
                      <span className="pill alt">Client-side Decryption</span>
                    </div>
                    
                    <div className="input-group">
                      <label>File ID from Sender</label>
                      <div className="file-id-input-group">
                        <input
                          placeholder="Paste the File ID here"
                          value={downloadFileId}
                          onChange={(e) => setDownloadFileId(e.target.value)}
                          disabled={loading}
                        />
                        <button 
                          className="btn-icon paste-btn" 
                          onClick={pasteFromClipboard}
                          title="Paste from clipboard"
                          disabled={loading}
                        >
                          <Copy size={16} />
                        </button>
                      </div>
                    </div>
                    
                    <div className="download-guide">
                      <h4>How to download files:</h4>
                      <ol className="download-steps">
                        <li>Ask the sender for the <strong>File ID</strong></li>
                        <li>Paste or type the File ID above</li>
                        <li>Click "Download & Decrypt"</li>
                        <li>The file will be decrypted locally and downloaded</li>
                      </ol>
                      
                      <div className="file-id-example">
                        <p className="tiny muted">Example File ID format:</p>
                        <code className="example-id">550e8400-e29b-41d4-a716-446655440000</code>
                      </div>
                    </div>
                    
                    <button className="btn primary full-width" onClick={downloadFile} disabled={loading}>
                      <Download size={18} />
                      Download & Decrypt File
                    </button>
                  </div>
                </div>
              )}

              {activeTab === 'sessions' && (
                <div className="panel full-width">
                  <HandshakeStatus key={sessionVersion} sessions={sessionsRef.current} />
                </div>
              )}

              {activeTab === 'logs' && (
                <div className="panel full-width">
                  <div className="panel-head">
                    <div className="panel-title">
                      <RefreshCw size={20} />
                      <div>
                        <p className="eyebrow">System Logs</p>
                        <h3>Activity & Status</h3>
                      </div>
                    </div>
                    <span className="pill alt">Real-time Updates</span>
                  </div>
                  <div className="logs-container">
                    <div className="logs-header">
                      <h4>Event Timeline</h4>
                      <button 
                        className="btn-icon ghost" 
                        onClick={() => setStatus([])}
                        disabled={status.length === 0}
                      >
                        Clear Logs
                      </button>
                    </div>
                    <div className="logs-list">
                      {status.length === 0 ? (
                        <div className="empty-logs">
                          <RefreshCw size={48} className="muted" />
                          <p className="muted">No activity logs yet</p>
                          <p className="tiny">Perform actions to see real-time status updates</p>
                        </div>
                      ) : (
                        status.map((s, i) => (
                          <div key={i} className="log-entry">
                            <div className="log-icon">
                              {s.includes('✅') ? '✅' : s.includes('❌') ? '❌' : s.includes('⚠️') ? '⚠️' : 'ℹ️'}
                            </div>
                            <div className="log-content">
                              <span className="log-message">{s.replace(/^[✅❌⚠️ℹ️]\s*/, '')}</span>
                              <span className="log-time tiny muted">
                                {s.match(/\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)/)?.[0] || ''}
                              </span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* MITM Demo Tab */}
              {activeTab === 'mitm' && (
                <div className="mitm-demo-container">
                  <MitmDemo />
                </div>
              )}
            </div>
          </>
        )}
      </main>

      {/* Loading Overlay */}
      {loading && (
        <div className="loading-overlay">
          <div className="loading-spinner"></div>
          <p>Processing...</p>
        </div>
      )}

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <div className="security-badges">
            <span className="pill">AES-256-GCM</span>
            <span className="pill alt">ECDH-P256</span>
            <span className="pill">HKDF-SHA256</span>
            <span className="pill alt">End-to-End</span>
            <span className="pill">MITM-Protected</span>
          </div>
          <p className="tiny muted">
            All cryptographic operations performed locally • Server only sees ciphertext • No backdoors
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;