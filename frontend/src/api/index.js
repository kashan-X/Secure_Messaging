import api, { setAuthToken } from './client';

export const registerUser = async ({ username, password, identityPublicKey }) => {
  const res = await api.post('/auth/register', { username, password, identityPublicKey });
  return res.data;
};

export const loginUser = async ({ username, password }) => {
  const res = await api.post('/auth/login', { username, password });
  const { token, user } = res.data;
  setAuthToken(token);
  return { token, user };
};

export const lookupUser = async (username) => {
  const res = await api.get(`/users/${encodeURIComponent(username)}/public-key`);
  return res.data; // {id, username, identityPublicKey}
};

export const sendMessage = async (payload) => {
  const res = await api.post('/messages', payload);
  return res.data;
};

export const fetchInbox = async (type) => {
  const res = await api.get('/messages/inbox', { params: { type } });
  return res.data.messages;
};

export const fetchThread = async (peerId) => {
  const res = await api.get(`/messages/thread/${peerId}`);
  return res.data.messages;
};

export const clientAudit = async (event, details) => {
  try {
    await api.post('/logs/client', { event, details });
  } catch {
    // Best-effort; ignore failures to avoid breaking UX.
  }
};

export const initFileTransfer = async (payload) => {
  const res = await api.post('/files/init', payload);
  return res.data;
};

export const uploadChunk = async (fileId, payload) => {
  const res = await api.post(`/files/${fileId}/chunk`, payload);
  return res.data;
};

export const fetchFileChunks = async (fileId) => {
  const res = await api.get(`/files/${fileId}/chunks`);
  return res.data;
};
