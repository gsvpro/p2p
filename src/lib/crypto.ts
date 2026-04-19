/**
 * SubtleCrypto helpers for E2EE
 */

export async function generateIdentity(): Promise<{ publicKey: string; privateKey: CryptoKey }> {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey']
  );

  const exportedPublic = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyBase64 = b64encode(exportedPublic);

  return {
    publicKey: publicKeyBase64,
    privateKey: keyPair.privateKey,
  };
}

export async function deriveSharedSecret(
  privateKey: CryptoKey,
  peerPublicKeyBase64: string
): Promise<CryptoKey> {
  const peerPublicKeyBuffer = b64decode(peerPublicKeyBase64);
  const peerPublicKey = await window.crypto.subtle.importKey(
    'spki',
    peerPublicKeyBuffer,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    []
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: peerPublicKey,
    },
    privateKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
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

// Utils
function b64encode(buf: ArrayBuffer): string {
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
