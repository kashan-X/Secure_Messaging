const STATE_KEY = 'replay-state';

const loadState = () => {
  try {
    const raw = localStorage.getItem(STATE_KEY);
    return raw ? JSON.parse(raw) : { seqOut: {}, seqIn: {}, nonces: {} };
  } catch {
    return { seqOut: {}, seqIn: {}, nonces: {} };
  }
};

const saveState = (state) => localStorage.setItem(STATE_KEY, JSON.stringify(state));

export const nextSeq = (peerId) => {
  const state = loadState();
  const current = state.seqOut[peerId] || 0;
  const next = current + 1;
  state.seqOut[peerId] = next;
  saveState(state);
  return next;
};

export const recordInboundSeq = (peerId, seq) => {
  const state = loadState();
  const last = state.seqIn[peerId] || 0;
  if (seq <= last) {
    throw new Error('replay_detected');
  }
  state.seqIn[peerId] = seq;
  saveState(state);
};

export const recordNonce = (nonceB64, scope) => {
  const state = loadState();
  const key = scope || 'global';
  const list = state.nonces[key] || [];
  if (list.includes(nonceB64)) {
    throw new Error('nonce_replay');
  }
  const trimmed = [nonceB64, ...list].slice(0, 50);
  state.nonces[key] = trimmed;
  saveState(state);
};
