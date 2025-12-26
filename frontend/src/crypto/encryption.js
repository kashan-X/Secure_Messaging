import { base64ToBuf, bufToBase64, concatBuffers, randomBytes, utf8ToBuf } from './utils';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const sha256 = async (data) => {
  const buf = typeof data === 'string' ? utf8ToBuf(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return hash;
};

export const hkdf = async ({ secret, salt, info, length }) => {
  const keyMaterial = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    keyMaterial,
    length * 8
  );
  return bits;
};

export const deriveSessionKeys = async ({ sharedSecret, nonceA, nonceB, aid, bid }) => {
  const salt = concatBuffers([nonceA, nonceB]);
  const info = utf8ToBuf(`e2ee-handshake-v1|${aid}|${bid}`);
  const material = await hkdf({ secret: sharedSecret, salt, info, length: 96 });
  const bytes = new Uint8Array(material);
  return {
    kEnc: bytes.slice(0, 32).buffer,
    kFile: bytes.slice(32, 64).buffer,
    kConfirm: bytes.slice(64, 96).buffer,
  };
};

export const hmacSha256 = async (keyBytes, data) => {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const payload = typeof data === 'string' ? textEncoder.encode(data) : data;
  return crypto.subtle.sign('HMAC', key, payload);
};

const importAesKey = (raw) =>
  crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);

export const encryptMessage = async ({ key, plaintext, aad }) => {
  const aesKey = await importAesKey(key);
  const iv = randomBytes(12);
  const aadBuf = aad ? utf8ToBuf(aad) : undefined;
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aadBuf },
    aesKey,
    utf8ToBuf(plaintext)
  );
  const ctBytes = new Uint8Array(ct);
  const authTag = ctBytes.slice(ctBytes.length - 16);
  const ciphertext = ctBytes.slice(0, ctBytes.length - 16);

  return {
    ciphertextB64: bufToBase64(ciphertext),
    authTagB64: bufToBase64(authTag),
    ivB64: bufToBase64(iv),
  };
};

export const decryptMessage = async ({ key, ciphertextB64, authTagB64, ivB64, aad }) => {
  const aesKey = await importAesKey(key);
  const iv = base64ToBuf(ivB64);
  const ciphertext = base64ToBuf(ciphertextB64);
  const authTag = base64ToBuf(authTagB64);
  const combined = concatBuffers([ciphertext, authTag]);
  const aadBuf = aad ? utf8ToBuf(aad) : undefined;
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: aadBuf },
    aesKey,
    combined
  );
  return textDecoder.decode(plaintext);
};

export const encryptChunk = async ({ key, chunkBytes, aad }) => {
  const aesKey = await importAesKey(key);
  const iv = randomBytes(12);
  const aadBuf = aad ? utf8ToBuf(aad) : undefined;
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aadBuf },
    aesKey,
    chunkBytes
  );
  const ctBytes = new Uint8Array(ct);
  const authTag = ctBytes.slice(ctBytes.length - 16);
  const ciphertext = ctBytes.slice(0, ctBytes.length - 16);

  return {
    ciphertextB64: bufToBase64(ciphertext),
    authTagB64: bufToBase64(authTag),
    ivB64: bufToBase64(iv),
  };
};

export const deriveFileKey = async (kFile, fileId) => {
  const salt = utf8ToBuf(fileId);
  const info = utf8ToBuf(`file-v1|${fileId}`);
  const derived = await hkdf({ secret: kFile, salt, info, length: 32 });
  return derived;
};

export const decryptChunk = async ({ key, ciphertextB64, authTagB64, ivB64, aad }) => {
  const aesKey = await importAesKey(key);
  const iv = base64ToBuf(ivB64);
  const ciphertext = base64ToBuf(ciphertextB64);
  const authTag = base64ToBuf(authTagB64);
  const combined = concatBuffers([ciphertext, authTag]);
  const aadBuf = aad ? utf8ToBuf(aad) : undefined;
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: aadBuf },
    aesKey,
    combined
  );
  return new Uint8Array(plaintext);
};
