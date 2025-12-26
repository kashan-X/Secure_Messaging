const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8ToBuf = (str) => encoder.encode(str);
export const bufToUtf8 = (buf) => decoder.decode(buf);

export const bufToBase64 = (buf) => {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer);
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
};

export const base64ToBuf = (b64) => {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

export const randomBytes = (len) => {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
};

export const concatBuffers = (buffers) => {
  const total = buffers.reduce((sum, b) => sum + b.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  buffers.forEach((b) => {
    const view = b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer);
    out.set(view, offset);
    offset += view.byteLength;
  });
  return out.buffer;
};

export const canonicalJson = (obj) => JSON.stringify(obj, Object.keys(obj).sort());
