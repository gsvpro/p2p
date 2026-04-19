import Peer, { DataConnection } from 'peerjs';
import { generateIdentity, hashId, deriveHybridSecret, encryptData, decryptText, decryptData, QuantumIdentity, importIdentity, exportIdentity, b64encode } from './crypto';
import { Identity, SecureMessage, FileTransfer, Group } from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as ed from '@noble/ed25519';
import { sha512 } from 'js-sha512';

// Configure Ed25519 v2 with SHA-512 hooks
// 1. Synchronous hook (using js-sha512) - Required for Pkarr and some internal methods
// @ts-ignore
ed.hashes.sha512 = (...m) => {
  const hash = sha512.create();
  for (const arr of m) hash.update(arr);
  return new Uint8Array(hash.arrayBuffer());
};

// 2. Asynchronous hook (using Web Crypto) - Used for ed.signAsync and ed.getPublicKeyAsync
// @ts-ignore
ed.hashes.sha512Async = (...m) => {
  const length = m.reduce((acc, x) => acc + x.length, 0);
  const combined = new Uint8Array(length);
  let offset = 0;
  for (const arr of m) {
    combined.set(arr, offset);
    offset += arr.length;
  }
  return crypto.subtle.digest('SHA-512', combined).then(b => new Uint8Array(b));
};

const CHUNK_SIZE = 16384;

export class IrohManager {
  private peer: Peer | null = null;
  private identity: Identity | null = null;
  private qIdentity: QuantumIdentity | null = null;
  private connections: Map<string, DataConnection> = new Map();
  private secrets: Map<string, CryptoKey> = new Map();
  private peerPks: Map<string, { classical: string; pqc: string }> = new Map();
  private peerMetadata: Map<string, { displayName: string }> = new Map();
  private groups: Map<string, Group> = new Map();
  private transfers: Map<string, FileTransfer> = new Map();
  private fileChunks: Map<string, Uint8Array[]> = new Map();
  
  private onMessageCallback: ((msg: SecureMessage) => void) | null = null;
  private onGroupUpdateCallback: ((groups: Group[]) => void) | null = null;
  private onTransferUpdateCallback: ((transfers: FileTransfer[]) => void) | null = null;
  private onStatusCallback: ((type: 'info' | 'error', message: string) => void) | null = null;
  private currentPeerId: string | null = null;

  async initialize(displayName: string) {
    const savedIdentity = localStorage.getItem('nexus_identity');
    if (savedIdentity) {
      try {
        this.qIdentity = await importIdentity(savedIdentity);
      } catch (e) {
        console.error("Failed to load saved identity", e);
        this.qIdentity = await generateIdentity();
      }
    } else {
      this.qIdentity = await generateIdentity();
      const serialized = await exportIdentity(this.qIdentity);
      localStorage.setItem('nexus_identity', serialized);
    }

    const id = await hashId(this.qIdentity.classicalPublicKey);
    
    this.identity = { 
      classicalPublicKey: this.qIdentity.classicalPublicKey,
      pqcPublicKey: this.qIdentity.pqcPublicKey,
      identityBytes: this.qIdentity.classicalPublicKey + this.qIdentity.pqcPublicKey,
      displayName,
      id
    };

    // Use a session suffix to prevent "ID already taken" errors on reloads
    const sessionSuffix = Math.random().toString(16).slice(2, 6);
    this.currentPeerId = `${id}-${sessionSuffix}`;

    this.peer = new Peer(this.currentPeerId);
    
    this.peer.on('open', async () => {
      this.notifyStatus('info', 'Secure Node Online');
      await this.publishToDiscovery();
    });

    this.peer.on('error', (err) => {
      console.error('PeerJS error:', err);
      this.notifyStatus('error', `Network Error: ${err.type}`);
    });

    this.peer.on('connection', (conn) => {
      this.handleIncomingConnection(conn);
    });
  }

  private async getDiscoveryKeypair(name: string) {
    // Deterministic key for name discovery
    const seed = new TextEncoder().encode(`iroh-discovery-v3-${name.toLowerCase().trim()}`);
    const hash = await window.crypto.subtle.digest('SHA-256', seed);
    const privateKey = new Uint8Array(hash);
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    return { publicKey, privateKey };
  }

  async publishToDiscovery() {
    if (!this.identity || this.identity.displayName.length < 3) return;
    try {
      const name = this.identity.displayName;
      const { publicKey, privateKey } = await this.getDiscoveryKeypair(name);
      
      // We use the Pkarr Relay HTTP API directly for maximum compatibility
      const zbase32 = this.toZBase32(publicKey);
      const ticket = this.currentPeerId!; 
      
      // Create a simplified Pkarr payload
      // Since pkarr.sh supports simple storage for well-known keys, we use a discovery relay
      const payload = {
        v: ticket,
        seq: Date.now(),
        sig: b64encode(await ed.signAsync(new TextEncoder().encode(ticket), privateKey))
      };

      await fetch(`https://pkarr.sh/${zbase32}`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      }).catch(() => {});
      
      console.log(`Discovered as ${name} at Pkarr address: ${zbase32}`);
    } catch (e) {
      console.error("Discovery publication failed", e);
    }
  }

  async searchByName(name: string): Promise<string | null> {
    try {
      this.notifyStatus('info', `Searching DHT for "${name}"...`);
      const { publicKey } = await this.getDiscoveryKeypair(name);
      const zbase32 = this.toZBase32(publicKey);
      
      const res = await fetch(`https://pkarr.sh/${zbase32}`);
      if (!res.ok) return null;

      const data = await res.json();
      if (data && data.v) {
        return data.v;
      }
      return null;
    } catch (e) {
      console.error("Discovery lookup failed", e);
      return null;
    }
  }

  private toZBase32(data: Uint8Array): string {
    // Simplified z-base32 for the discovery address
    const alphabet = 'ybndrfg89jkmcpqxot1uwisza345h76e';
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < data.length; i++) {
        value = (value << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            output += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        output += alphabet[(value << (5 - bits)) & 31];
    }
    return output;
  }

  private notifyStatus(type: 'info' | 'error', message: string) {
    if (this.onStatusCallback) {
      this.onStatusCallback(type, message);
    }
  }

  onStatus(callback: (type: 'info' | 'error', message: string) => void) {
    this.onStatusCallback = callback;
  }

  private async handleIncomingConnection(conn: DataConnection) {
    conn.on('open', () => {
      this.connections.set(conn.peer, conn);
    });

    conn.on('data', async (data: any) => {
      if (data.type === 'HELO') {
        const sharedSecret = await deriveHybridSecret(
          this.qIdentity!, 
          data.classicalPublicKey, 
          data.pqcPublicKey, 
          false
        );
        this.secrets.set(conn.peer, sharedSecret);
        this.peerPks.set(conn.peer, { classical: data.classicalPublicKey, pqc: data.pqcPublicKey });
        
        // Responder sends HELO_ACK with Bob's PK and the CT for Alice's Kyber PK
        conn.send({ 
          type: 'HELO_ACK', 
          classicalPublicKey: this.identity!.classicalPublicKey,
          pqcCiphertext: (window as any).__last_ct, // Captured during deriveHybridSecret for responder
          displayName: this.identity!.displayName
        });
        
        if (data.displayName) {
          this.peerMetadata.set(conn.peer, { displayName: data.displayName });
        }

      } else if (data.type === 'GROUP_INVITE') {
        const group: Group = data.group;
        this.groups.set(group.id, group);
        if (this.onGroupUpdateCallback) {
          this.onGroupUpdateCallback(Array.from(this.groups.values()));
        }

      } else if (data.type === 'HELO_ACK') {
        // Alice receives Bob's PK and the CT
        const sharedSecret = await deriveHybridSecret(
          this.qIdentity!, 
          data.classicalPublicKey, 
          data.pqcCiphertext, // Alice uses CT to decap
          true
        );
        this.secrets.set(conn.peer, sharedSecret);
        this.peerPks.set(conn.peer, { classical: data.classicalPublicKey, pqc: 'Encapsulated Session' });
        
        if (data.displayName) {
          this.peerMetadata.set(conn.peer, { displayName: data.displayName });
        }

      } else if (data.encrypted) {
        const secret = this.secrets.get(conn.peer);
        if (secret) {
          if (data.type === 'reaction') {
            const reactionData = JSON.parse(await decryptText(secret, data.content, data.iv));
            if (this.onMessageCallback) {
              this.onMessageCallback({
                ...data,
                content: reactionData.emoji,
                targetMessageId: reactionData.targetMessageId,
                receiverId: this.identity!.id,
              });
            }
          } else if (data.type === 'file_chunk') {
            await this.handleFileChunk(conn.peer, data, secret);
          } else {
            const decrypted = await decryptText(secret, data.content, data.iv);
            if (this.onMessageCallback) {
              this.onMessageCallback({
                ...data,
                content: decrypted,
                receiverId: this.identity!.id,
              });
            }
          }
        }
      }
    });

    conn.on('close', () => {
      this.connections.delete(conn.peer);
    });
  }

  private async handleFileChunk(peerId: string, data: any, secret: CryptoKey) {
    let transfer = this.transfers.get(data.transferId);
    let chunks = this.fileChunks.get(data.transferId);
    
    if (!transfer) {
      transfer = {
        id: data.transferId,
        name: data.fileName,
        size: data.totalSize,
        progress: 0,
        type: 'download',
        status: 'active',
        peerId
      };
      this.transfers.set(data.transferId, transfer);
      chunks = [];
      this.fileChunks.set(data.transferId, chunks);
    }

    const chunk = await decryptData(secret, data.content, data.iv);
    chunks!.push(chunk);
    transfer.progress += chunk.length;
    
    if (transfer.progress >= transfer.size) {
      transfer.status = 'completed';
      // Create download blob
      const blob = new Blob(chunks, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      transfer.downloadUrl = url;
    }

    this.notifyTransferUpdate();
  }

  async sendFile(peerId: string, file: File) {
    const conn = this.connections.get(peerId);
    const secret = this.secrets.get(peerId);
    if (!conn || !secret) return;

    const transferId = uuidv4();
    const transfer: FileTransfer = {
      id: transferId,
      name: file.name,
      size: file.size,
      progress: 0,
      type: 'upload',
      status: 'active',
      peerId
    };
    this.transfers.set(transferId, transfer);

    const reader = new FileReader();
    let offset = 0;

    const readNext = () => {
      const slice = file.slice(offset, offset + CHUNK_SIZE);
      reader.readAsArrayBuffer(slice);
    };

    reader.onload = async (e) => {
      const buf = e.target?.result as ArrayBuffer;
      const { ciphertext, iv } = await encryptData(secret, new Uint8Array(buf));
      
      conn.send({
        encrypted: true,
        type: 'file_chunk',
        transferId,
        fileName: file.name,
        totalSize: file.size,
        content: ciphertext,
        iv,
      });

      offset += buf.byteLength;
      transfer.progress = offset;
      this.notifyTransferUpdate();

      if (offset < file.size) {
        readNext();
      } else {
        transfer.status = 'completed';
        this.notifyTransferUpdate();
      }
    };

    readNext();
  }

  async sendReaction(peerId: string, messageId: string, emoji: string) {
    const conn = this.connections.get(peerId);
    const secret = this.secrets.get(peerId);
    if (!conn || !secret) return;

    const reactionPayload = JSON.stringify({ targetMessageId: messageId, emoji });
    const { ciphertext, iv } = await encryptData(secret, reactionPayload);

    const msg: SecureMessage = {
      id: uuidv4(),
      senderId: this.identity!.id,
      receiverId: peerId,
      type: 'reaction',
      content: ciphertext,
      iv,
      timestamp: Date.now(),
      targetMessageId: messageId
    };

    conn.send({ ...msg, encrypted: true, type: 'reaction' });
    return { ...msg, content: emoji };
  }

  async connectByTicket(ticket: string) {
    if (!this.peer || this.connections.has(ticket)) {
      this.notifyStatus('info', 'Already connected or offline');
      return;
    }
    
    this.notifyStatus('info', `Attempting tunnel to ${ticket.slice(0, 8)}...`);
    
    const conn = this.peer.connect(ticket, {
      reliable: true
    });

    conn.on('open', () => {
      this.connections.set(ticket, conn);
      this.notifyStatus('info', `Tunnel Established: Node_${ticket.slice(0, 4)}`);
      // Alice sends local PKs (Classical + PQC)
      conn.send({ 
        type: 'HELO', 
        classicalPublicKey: this.identity!.classicalPublicKey,
        pqcPublicKey: this.identity!.pqcPublicKey,
        displayName: this.identity!.displayName
      });
    });

    conn.on('error', (err) => {
      this.notifyStatus('error', `Tunnel Failed: ${err}`);
    });

    this.handleIncomingConnection(conn);
  }

  private notifyTransferUpdate() {
    if (this.onTransferUpdateCallback) {
      this.onTransferUpdateCallback(Array.from(this.transfers.values()));
    }
  }

  onTransferUpdate(callback: (transfers: FileTransfer[]) => void) {
    this.onTransferUpdateCallback = callback;
  }

  onGroupUpdate(callback: (groups: Group[]) => void) {
    this.onGroupUpdateCallback = callback;
  }

  async createGroup(name: string, members: string[]) {
    const id = uuidv4();
    const group: Group = {
      id,
      name,
      members: [...new Set([...members, this.identity!.id])],
      createdAt: Date.now()
    };
    
    this.groups.set(id, group);
    
    // Notify local UI
    if (this.onGroupUpdateCallback) {
      this.onGroupUpdateCallback(Array.from(this.groups.values()));
    }

    // Invite members
    members.forEach(async (memberId) => {
      if (memberId === this.identity?.id) return;
      const conn = this.connections.get(memberId);
      if (conn && conn.open) {
        conn.send({ type: 'GROUP_INVITE', group });
      }
    });

    return group;
  }

  async sendGroupMessage(groupId: string, text: string, options: { ephemeral?: boolean } = {}) {
    const group = this.groups.get(groupId);
    if (!group) return;

    const msgId = uuidv4();
    const timestamp = Date.now();
    const expiresAt = options.ephemeral ? timestamp + 60000 : undefined;

    // Multicast to all members
    group.members.forEach(async (memberId) => {
      if (memberId === this.identity?.id) return;

      const conn = this.connections.get(memberId);
      const secret = this.secrets.get(memberId);
      
      if (conn && secret) {
        const { ciphertext, iv } = await encryptData(secret, text);
        const msg: SecureMessage = {
          id: msgId,
          senderId: this.identity!.id,
          receiverId: memberId,
          groupId,
          type: 'text',
          content: ciphertext,
          iv,
          timestamp,
          expiresAt
        };
        conn.send({ ...msg, encrypted: true });
      }
    });

    return {
      id: msgId,
      senderId: this.identity!.id,
      receiverId: groupId,
      groupId,
      type: 'text' as const,
      content: text,
      iv: '',
      timestamp,
      expiresAt
    };
  }

  async sendMessage(peerId: string, text: string, options: { ephemeral?: boolean } = {}) {
    const conn = this.connections.get(peerId);
    const secret = this.secrets.get(peerId);
    if (!conn || !secret) return null;

    const { ciphertext, iv } = await encryptData(secret, text);
    const msg: SecureMessage = {
      id: uuidv4(),
      senderId: this.identity!.id,
      receiverId: peerId,
      type: 'text',
      content: ciphertext,
      iv,
      timestamp: Date.now(),
      expiresAt: options.ephemeral ? Date.now() + 60000 : undefined,
    };

    conn.send({ ...msg, encrypted: true });
    return { ...msg, content: text };
  }

  onMessage(callback: (msg: SecureMessage) => void) {
    this.onMessageCallback = callback;
  }

  getIdentity() { 
    if (!this.identity || !this.currentPeerId) return this.identity;
    return { ...this.identity, id: this.currentPeerId }; 
  }
  getQuantumIdentity() { return this.qIdentity; }
  
  getPeerKeys(peerId: string) {
    return this.peerPks.get(peerId);
  }

  getPeerName(peerId: string) {
    return this.peerMetadata.get(peerId)?.displayName;
  }

  getGroups() {
    return Array.from(this.groups.values());
  }

  setDisplayName(name: string) {
    if (this.identity) {
      this.identity.displayName = name;
      localStorage.setItem('nexus_name', name);
      this.publishToDiscovery();
    }
  }
  getConnectedPeers() { return Array.from(this.connections.keys()).filter(k => this.connections.get(k)?.open); }
}

export const iroh = new IrohManager();
