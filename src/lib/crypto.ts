/**
 * SubtleCrypto helpers for E2EE
 */

import { MlKem1024 } from 'crystals-kyber-js';

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
): Promise<CryptoKey> {
  const kem = new MlKem1024();
  let ssClassical: ArrayBuffer;
  let ssPqc: Uint8Array;

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
    // We are Alice, we received Bob's pk and we already sent ours? 
    // Actually, following Signal PQXDH:
    // Alice sends pk_A. Bob sends pk_B + ct_A (encapsulated for Alice's pk_A).
    // In our simplified P2P:
    // Initiator sends pk_c_A, pk_q_A
    // Responder receives and encaps for pk_q_A -> gets ss_pqc and ct_A.
    // Responder sends pk_c_B, ct_A
    // Initiator receives CT and decaps with sk_q_A -> gets ss_pqc.
    
    // PeerPqcPKOrCT is CT here
    ssPqc = await kem.decap(b64decode(peerPqcPKOrCT), identity.pqcPrivateKey);
  } else {
    // PeerPqcPKOrCT is Alice's PK here
    // We perform encapsulation
    const [ct, ss] = await kem.encap(b64decode(peerPqcPKOrCT));
    ssPqc = ss;
    // We need to return this CT back to Alice in the HELO_ACK
    (window as any).__last_ct = b64encode(ct); 
  }

  // 3. Hybrid Combination via HKDF
  // Secret = HKDF( ssClassical || ssPqc )
  const combinedSecret = new Uint8Array(ssClassical.byteLength + ssPqc.byteLength);
  combinedSecret.set(new Uint8Array(ssClassical), 0);
  combinedSecret.set(ssPqc, ssClassical.byteLength);

  return deriveKeyFromMaster(combinedSecret);
}

async function deriveKeyFromMaster(master: Uint8Array): Promise<CryptoKey> {
  const masterKey = await window.crypto.subtle.importKey(
    'raw',
    master,
    'HKDF',
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
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
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}
