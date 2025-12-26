import { openDB } from 'idb';
import { base64ToBuf, bufToBase64, canonicalJson, randomBytes, utf8ToBuf } from './utils';

// Use a fresh DB name to avoid stale/missing object stores from older versions.
const DB_NAME = 'e2ee-keys-v2';
const STORE = 'identity';

const DB_VERSION = 1;

const getDb = async () => {
  try {
    const db = await openDB(DB_NAME, DB_VERSION, {
      upgrade(dbUpgrade) {
        if (!dbUpgrade.objectStoreNames.contains(STORE)) {
          dbUpgrade.createObjectStore(STORE, { keyPath: 'id' });
        }
      },
    });
    if (!db.objectStoreNames.contains(STORE)) {
      // defensive: recreate if somehow missing
      await indexedDB.deleteDatabase(DB_NAME);
      const recreated = await openDB(DB_NAME, DB_VERSION, {
        upgrade(dbUpgrade) {
          dbUpgrade.createObjectStore(STORE, { keyPath: 'id' });
        },
      });
      return recreated;
    }
    return db;
  } catch (err) {
    console.warn('IndexedDB issue, resetting key store', err);
    await indexedDB.deleteDatabase(DB_NAME);
    return openDB(DB_NAME, DB_VERSION, {
      upgrade(dbUpgrade) {
        dbUpgrade.createObjectStore(STORE, { keyPath: 'id' });
      },
    });
  }
};

export const generateIdentityKeyPair = async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { keyPair, publicJwk };
};

export const generateEphemeralKeyPair = async () => {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
};

const derivePasswordKey = async (password, salt) => {
  const keyMaterial = await crypto.subtle.importKey('raw', utf8ToBuf(password), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 310000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

export const encryptPrivateKey = async (privateKey, password) => {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const aesKey = await derivePasswordKey(password, salt);
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const plaintext = utf8ToBuf(canonicalJson(jwk));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
  return {
    ciphertext: bufToBase64(ciphertext),
    iv: bufToBase64(iv),
    salt: bufToBase64(salt),
  };
};

export const decryptPrivateKey = async (encrypted, password) => {
  const salt = base64ToBuf(encrypted.salt);
  const iv = base64ToBuf(encrypted.iv);
  const aesKey = await derivePasswordKey(password, salt);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    aesKey,
    base64ToBuf(encrypted.ciphertext)
  );
  const jwk = JSON.parse(new TextDecoder().decode(plaintext));
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
  ]);
};

export const saveIdentityKey = async (userId, encryptedPrivateKey, publicKeyJwk) => {
  try {
    const db = await getDb();
    const tx = db.transaction(STORE, 'readwrite');
    await tx.store.put({ id: userId, encryptedPrivateKey, publicKeyJwk });
    await tx.done;
  } catch (err) {
    console.warn('resetting key store after put failure', err);
    await indexedDB.deleteDatabase(DB_NAME);
    const db = await getDb();
    const tx = db.transaction(STORE, 'readwrite');
    await tx.store.put({ id: userId, encryptedPrivateKey, publicKeyJwk });
    await tx.done;
  }
};

export const loadIdentityRecord = async (userId) => {
  const db = await getDb();
  return db.get(STORE, userId);
};

export const deleteIdentityKey = async (userId) => {
  const db = await getDb();
  await db.delete(STORE, userId);
};
