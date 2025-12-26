import { base64ToBuf, bufToBase64, canonicalJson, randomBytes, utf8ToBuf } from './utils';
import { deriveSessionKeys, hmacSha256, sha256 } from './encryption';
import { generateEphemeralKeyPair } from './keys';
import { nextSeq, recordNonce } from './replay';

const ALG = 'P-256+HKDF+AES-256-GCM';

const exportKey = (key) => crypto.subtle.exportKey('jwk', key);

const importIdentityPublic = (jwk) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

const importEcdhPublic = (jwk) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);

const deriveSharedSecret = async (privateKey, peerPubJwk) => {
  const peerPub = await importEcdhPublic(peerPubJwk);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, privateKey, 256);
  return bits;
};

const signPayload = async (privateKey, payload) => {
  const data = utf8ToBuf(canonicalJson(payload));
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
  return bufToBase64(signature);
};

const verifySignature = async (publicJwk, payload, signatureB64) => {
  const key = await importIdentityPublic(publicJwk);
  const data = utf8ToBuf(canonicalJson(payload));
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    base64ToBuf(signatureB64),
    data
  );
};

const computeTranscriptHash = async ({ aid, bid, init, resp }) => {
  const transcript = canonicalJson({
    aid,
    bid,
    A_eph_pub: init.A_eph_pub,
    B_eph_pub: resp.B_eph_pub,
    nonceA: init.nonceA,
    nonceB: resp.nonceB,
    tsA: init.tsA,
    tsB: resp.tsB,
    seqA: init.seqA,
    seqB: resp.seqB,
  });
  const hash = await sha256(utf8ToBuf(transcript));
  return bufToBase64(hash);
};

export const createInitHandshake = async ({ self, peer, identityPrivateKey, identityPublicJwk }) => {
  const eph = await generateEphemeralKeyPair();
  const A_eph_pub = await exportKey(eph.publicKey);
  const nonceA = randomBytes(12);
  const tsA = Date.now();
  const seqA = nextSeq(peer.id);

  const signaturePayload = {
    A_eph_pub,
    nonceA: bufToBase64(nonceA),
    tsA,
    seqA,
    bid: peer.id,
    alg: ALG,
  };
  const sigA = await signPayload(identityPrivateKey, signaturePayload);

  const envelope = {
    stage: 'init',
    aid: self.id,
    bid: peer.id,
    alg: ALG,
    tsA,
    seqA,
    nonceA: bufToBase64(nonceA),
    A_eph_pub,
    A_id_pub: identityPublicJwk,
    sigA,
  };

  const state = { ephPriv: eph.privateKey, envelope };
  return { envelope, state };
};

export const handleInit = async ({ envelope, self, identityPrivateKey, peerPublicJwk }) => {
  // replay guard on nonce
  recordNonce(envelope.nonceA, envelope.aid);

  const validSig = await verifySignature(
    envelope.A_id_pub || peerPublicJwk,
    {
      A_eph_pub: envelope.A_eph_pub,
      nonceA: envelope.nonceA,
      tsA: envelope.tsA,
      seqA: envelope.seqA,
      bid: self.id,
      alg: envelope.alg,
    },
    envelope.sigA
  );
  if (!validSig) {
    throw new Error('invalid signature');
  }

  const eph = await generateEphemeralKeyPair();
  const B_eph_pub = await exportKey(eph.publicKey);
  const nonceB = randomBytes(12);
  const tsB = Date.now();
  const seqB = nextSeq(envelope.aid);

  const sharedSecret = await deriveSharedSecret(eph.privateKey, envelope.A_eph_pub);
  const { kEnc, kFile, kConfirm } = await deriveSessionKeys({
    sharedSecret,
    nonceA: base64ToBuf(envelope.nonceA),
    nonceB,
    aid: envelope.aid,
    bid: self.id,
  });

  const sigPayload = {
    B_eph_pub,
    nonceB: bufToBase64(nonceB),
    tsB,
    seqB,
    aid: envelope.aid,
    alg: envelope.alg,
  };
  const sigB = await signPayload(identityPrivateKey, sigPayload);
  const transcriptHash = await computeTranscriptHash({
    aid: envelope.aid,
    bid: self.id,
    init: envelope,
    resp: { B_eph_pub, nonceB: bufToBase64(nonceB), tsB, seqB },
  });
  const confirmB = await hmacSha256(kConfirm, utf8ToBuf(`B|${transcriptHash}`));

  const response = {
    stage: 'resp',
    aid: envelope.aid,
    bid: self.id,
    alg: envelope.alg,
    tsB,
    seqB,
    nonceB: bufToBase64(nonceB),
    B_eph_pub,
    sigB,
    transcriptHash,
    confirmB: bufToBase64(confirmB),
  };

  const session = {
    peerId: envelope.aid,
    kEnc,
    kFile,
    kConfirm,
    transcriptHash,
    nonceA: envelope.nonceA,
    nonceB: bufToBase64(nonceB),
    status: 'waiting-confirm',
  };

  return { response, session };
};

export const finalizeHandshake = async ({ initState, responseEnvelope, peerPublicJwk }) => {
  recordNonce(responseEnvelope.nonceB, responseEnvelope.bid);

  const validSig = await verifySignature(
    peerPublicJwk,
    {
      B_eph_pub: responseEnvelope.B_eph_pub,
      nonceB: responseEnvelope.nonceB,
      tsB: responseEnvelope.tsB,
      seqB: responseEnvelope.seqB,
      aid: responseEnvelope.aid,
      alg: responseEnvelope.alg,
    },
    responseEnvelope.sigB
  );
  if (!validSig) {
    throw new Error('invalid signature');
  }

  const sharedSecret = await deriveSharedSecret(initState.ephPriv, responseEnvelope.B_eph_pub);
  const { kEnc, kFile, kConfirm } = await deriveSessionKeys({
    sharedSecret,
    nonceA: base64ToBuf(initState.envelope.nonceA),
    nonceB: base64ToBuf(responseEnvelope.nonceB),
    aid: initState.envelope.aid,
    bid: initState.envelope.bid,
  });

  const transcriptHash = await computeTranscriptHash({
    aid: initState.envelope.aid,
    bid: initState.envelope.bid,
    init: initState.envelope,
    resp: responseEnvelope,
  });
  const computedConfirmB = await hmacSha256(kConfirm, utf8ToBuf(`B|${transcriptHash}`));
  const providedConfirm = base64ToBuf(responseEnvelope.confirmB);
  if (bufToBase64(computedConfirmB) !== bufToBase64(providedConfirm)) {
    throw new Error('confirm_mismatch');
  }

  const confirmA = await hmacSha256(kConfirm, utf8ToBuf(`A|${transcriptHash}`));
  const confirmMsg = {
    stage: 'confirm',
    aid: initState.envelope.aid,
    bid: initState.envelope.bid,
    tsA2: Date.now(),
    seqA2: nextSeq(responseEnvelope.aid),
    transcriptHash,
    confirmA: bufToBase64(confirmA),
  };

  const session = {
    peerId: responseEnvelope.bid,
    kEnc,
    kFile,
    kConfirm,
    transcriptHash,
    nonceA: initState.envelope.nonceA,
    nonceB: responseEnvelope.nonceB,
    status: 'active', // initiator considers session active after sending CONFIRM
  };

  return { confirmMsg, session };
};

export const handleConfirm = async ({ session, confirmEnvelope }) => {
  const computed = await hmacSha256(session.kConfirm, utf8ToBuf(`A|${session.transcriptHash}`));
  if (bufToBase64(computed) !== confirmEnvelope.confirmA) {
    throw new Error('confirm_invalid');
  }
  return { ...session, status: 'active' };
};
