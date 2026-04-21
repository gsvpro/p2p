/**
 * SubtleCrypto helpers for E2EE
 */

import { MlKem1024 } from 'crystals-kyber-js';

// Bundler-safe crypto helpers
const wc = typeof window !== 'undefined' ? window.crypto : null;
const wcs = wc?.subtle;

export interface QuantumIdentity {
  classicalPublicKey: string; // Base64 ECDH
  pqcPublicKey: string; // Base64 Kyber
  classicalPrivateKey: CryptoKey;
  pqcPrivateKey: Uint8Array;
}

export async function generateIdentity(): Promise<QuantumIdentity> {
  // 1. Classical P-256
  const classicalKeyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  const exportedPublic = await window.crypto.subtle.exportKey('spki', classicalKeyPair.publicKey);
  
  // 2. Post-Quantum Kyber-1024
  const kem = new MlKem1024();
  const [pk, sk] = await kem.generateKeyPair();

  return {
    classicalPublicKey: b64encode(exportedPublic),
    pqcPublicKey: b64encode(pk),
    classicalPrivateKey: classicalKeyPair.privateKey,
    pqcPrivateKey: sk
  };
}

export async function deriveHybridSecret(
  identity: QuantumIdentity,
  peerClassicalPK: string,
  peerPqcPKOrCT: string,
  isInitiator: boolean
): Promise<{ secret: CryptoKey; ciphertext?: string; secretBytes?: string }> {
  const kem = new MlKem1024();
  let ssClassical: ArrayBuffer;
  let ssPqc: Uint8Array;
  let ciphertext: string | undefined;

  // 1. Classical ECDH Derivation
  const peerClassicalKey = await window.crypto.subtle.importKey(
    'spki',
    b64decode(peerClassicalPK),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  ssClassical = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerClassicalKey },
    identity.classicalPrivateKey,
    256
  );

  // 2. PQC Kyber Derivation
  if (isInitiator) {
    ssPqc = await kem.decap(b64decode(peerPqcPKOrCT), identity.pqcPrivateKey);
  } else {
    const [ct, ss] = await kem.encap(b64decode(peerPqcPKOrCT));
    ssPqc = ss;
    ciphertext = b64encode(ct);
  }

  // 3. Hybrid Combination via HKDF
  const combinedSecret = new Uint8Array(ssClassical.byteLength + ssPqc.byteLength);
  combinedSecret.set(new Uint8Array(ssClassical), 0);
  combinedSecret.set(ssPqc, ssClassical.byteLength);

  const secret = await deriveKeyFromMaster(combinedSecret);
  return { secret, ciphertext, secretBytes: b64encode(combinedSecret) };
}

async function deriveKeyFromMaster(master: Uint8Array): Promise<CryptoKey> {
  const masterKey = await wc.subtle.importKey(
    'raw',
    master,
    'HKDF',
    false,
    ['deriveKey']
  );

  return wc.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: new Uint8Array(),
      info: new TextEncoder().encode('iroh-hybrid-v1'),
      hash: 'SHA-256',
    },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function encryptData(key: CryptoKey, data: string | Uint8Array): Promise<{ ciphertext: string; iv: string }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : data;

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encoded
  );

  return {
    ciphertext: b64encode(ciphertext),
    iv: b64encode(iv),
  };
}

export async function decryptData(key: CryptoKey, ciphertext: string, iv: string): Promise<Uint8Array> {
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: b64decode(iv),
    },
    key,
    b64decode(ciphertext)
  );

  return new Uint8Array(decrypted);
}

export async function decryptText(key: CryptoKey, ciphertext: string, iv: string): Promise<string> {
  const decrypted = await decryptData(key, ciphertext, iv);
  return new TextDecoder().decode(decrypted);
}

export async function exportIdentity(identity: QuantumIdentity): Promise<string> {
  const classicalPrivate = await window.crypto.subtle.exportKey('pkcs8', identity.classicalPrivateKey);
  return [
    identity.classicalPublicKey,
    identity.pqcPublicKey,
    b64encode(classicalPrivate),
    b64encode(identity.pqcPrivateKey)
  ].join('.');
}

export async function importIdentity(serialized: string): Promise<QuantumIdentity> {
  const [cpk, ppk, csk, psk] = serialized.split('.');
  
  const classicalPrivateKey = await window.crypto.subtle.importKey(
    'pkcs8',
    b64decode(csk),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  return {
    classicalPublicKey: cpk,
    pqcPublicKey: ppk,
    classicalPrivateKey,
    pqcPrivateKey: b64decode(psk)
  };
}

// Utils
export function b64encode(buf: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function hashId(publicKey: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(publicKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Double Ratchet implementation
export interface RatchetState {
  rootKey: CryptoKey;
  sendChainKey: CryptoKey;
  recvChainKey: CryptoKey;
  sendRatchetKey: CryptoKeyPair;
  recvRatchetKey: CryptoKeyPair;
  sendMessageNum: number;
  recvMessageNum: number;
  prevSendMessageNum: number;
  skippedKeys: Map<string, CryptoKey>;
}

interface CryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

const RATCHET_INFO = new TextEncoder().encode('ciphernexus-ratchet');
const CHAIN_KEY_INFO = new TextEncoder().encode('ciphernexus-chain');
const MESSAGE_KEY_INFO = new TextEncoder().encode('ciphernexus-message');

async function kdfRatchet(rootKey: CryptoKey, dhOutput: Uint8Array): Promise<{ rootKey: CryptoKey; chainKey: CryptoKey }> {
  const rootKeyBytes = await wcs.exportKey('raw', rootKey);
  const combined = new Uint8Array(dhOutput.length + 32);
  combined.set(new Uint8Array(rootKeyBytes), 0);
  combined.set(dhOutput, 32);
  
  const derive = async (key: Uint8Array, info: Uint8Array): Promise<CryptoKey> => {
    return wcs.deriveKey(
      { name: 'HKDF', salt: new Uint8Array(0), info, hash: 'SHA-256' },
      await wcs.importKey('raw', key, 'HKDF', false, ['deriveKey']),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  };
  
  const rootKeyResult = await derive(combined.slice(0, 32), RATCHET_INFO);
  const chainKey = await derive(combined.slice(32) || combined, CHAIN_KEY_INFO);
  
  return { rootKey: rootKeyResult, chainKey };
}

export async function initializeRatchet(secretBytes: string, isInitiator: boolean): Promise<RatchetState> {
  // Import from key bytes directly instead of trying to export from non-extractable key
  const keyBytes = b64decode(secretBytes);
  const rootKey = await wcs.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  
  // Generate initial ratchet key pair
  const sendRatchetKey = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  
  const recvRatchetKey = isInitiator ? sendRatchetKey : await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  
  // Initial chain keys
  const sendChainKey = await kdfRatchet(rootKey, new Uint8Array(32)).then(r => r.chainKey);
  const recvChainKey = await kdfRatchet(rootKey, new Uint8Array(32)).then(r => r.chainKey);
  
  return {
    rootKey,
    sendChainKey,
    recvChainKey,
    sendRatchetKey,
    recvRatchetKey,
    sendMessageNum: 0,
    recvMessageNum: 0,
    prevSendMessageNum: 0,
    skippedKeys: new Map()
  };
}

export async function deriveMessageKey(chainKey: CryptoKey): Promise<{ messageKey: CryptoKey; nextChainKey: CryptoKey }> {
  const chainKeyBytes = await window.crypto.subtle.exportKey('raw', chainKey);
  const chainArr = new Uint8Array(chainKeyBytes);
  
  // Derive message key (first 32 bytes)
  const msgKeyData = new Uint8Array(32);
  msgKeyData.set(chainArr.slice(0, 32), 0);
  const messageKey = await wcs.importKey('raw', msgKeyData, 'AES-GCM', false, ['encrypt', 'decrypt']);
  
  // Derive next chain key (last 32 bytes)  
  const nextChainData = new Uint8Array(32);
  nextChainData.set(chainArr.slice(32) || new Uint8Array(32), 0);
  const nextChainKey = await wcs.importKey('raw', nextChainData, 'AES-GCM', false, ['encrypt', 'decrypt']);
  
  return { messageKey, nextChainKey };
}

export async function ratchetEncrypt(state: RatchetState, plaintext: string): Promise<{ ciphertext: string; iv: string; state: RatchetState }> {
  // Derive message key from send chain
  const { messageKey, nextChainKey } = await deriveMessageKey(state.sendChainKey);
  
  // Encrypt with message key
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    messageKey,
    encoded
  );
  
  // Update state
  state.sendChainKey = nextChainKey;
  state.sendMessageNum++;
  
  return {
    ciphertext: b64encode(ciphertext),
    iv: b64encode(iv),
    state
  };
}

export async function ratchetDecrypt(state: RatchetState, ciphertext: string, iv: string): Promise<{ plaintext: string; state: RatchetState } | null> {
  const { messageKey, nextChainKey } = await deriveMessageKey(state.recvChainKey);
  
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(iv) },
      messageKey,
      b64decode(ciphertext)
    );
    
    state.recvChainKey = nextChainKey;
    state.recvMessageNum++;
    
    return {
      plaintext: new TextDecoder().decode(decrypted),
      state
    };
  } catch {
    return null;
  }
}
