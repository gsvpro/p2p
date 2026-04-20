import Peer, { DataConnection } from 'peerjs';
import * as dnsPacket from 'dns-packet';
import bencode from 'bencode';
import Pkarr, { z32, SignedPacket } from 'pkarr';
import { generateIdentity, hashId, deriveHybridSecret, encryptData, decryptText, decryptData, QuantumIdentity, importIdentity, exportIdentity, b64encode } from './crypto';
import { Identity, SecureMessage, FileTransfer, Group } from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as ed from '@noble/ed25519';
import { sha512 } from 'js-sha512';

const CHUNK_SIZE = 16384;
const dns = dnsPacket;

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

export class IrohManager {
  private peer: Peer | null = null;
  private identity: Identity | null = null;
  private qIdentity: QuantumIdentity | null = null;
  private connections: Map<string, DataConnection> = new Map();
  private secrets: Map<string, CryptoKey> = new Map();
  private peerPks: Map<string, { classical: string; pqc: string }> = new Map();
  private peerMetadata: Map<string, { displayName: string }> = new Map();
  private handshakeStatus: Map<string, boolean> = new Map();
  private groups: Map<string, Group> = new Map();
  private transfers: Map<string, FileTransfer> = new Map();
  private fileChunks: Map<string, Uint8Array[]> = new Map();
  
  private onMessageCallback: ((msg: SecureMessage) => void) | null = null;
  private onGroupUpdateCallback: ((groups: Group[]) => void) | null = null;
  private onTransferUpdateCallback: ((transfers: FileTransfer[]) => void) | null = null;
  private onStatusCallback: ((type: 'info' | 'error' | 'warning', message: string) => void) | null = null;
  private currentPeerId: string | null = null;
  private signalingWatchdog: any = null;

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
    
    // Stabilize session base during reloads in the same tab
    let sessionBase = sessionStorage.getItem('nexus_session_base');
    if (!sessionBase) {
      sessionBase = Math.random().toString(16).slice(2, 6);
      sessionStorage.setItem('nexus_session_base', sessionBase);
    }
    
    // Increment a "generation" counter for this tab to avoid collisions with the ghost session of the same tab
    let generation = parseInt(sessionStorage.getItem('nexus_generation') || '0');
    generation++;
    sessionStorage.setItem('nexus_generation', generation.toString());
    
    this.currentPeerId = `${id}-${sessionBase}-${generation}`;
    
    // Cleanup signaling on exit to help ID reuse
    window.addEventListener('beforeunload', () => {
      this.peer?.destroy();
    });

    await this.setupPeer(displayName);

    // Load persisted metadata
    const savedMetadata = localStorage.getItem('nexus_metadata');
    if (savedMetadata) {
      try {
        const metadata = JSON.parse(savedMetadata);
        Object.entries(metadata).forEach(([id, meta]: [string, any]) => {
          this.peerMetadata.set(id, meta);
        });
      } catch (e) {}
    }

    const savedGroups = localStorage.getItem('nexus_groups');
    if (savedGroups) {
      try {
        const groupsJson = JSON.parse(savedGroups);
        groupsJson.forEach((g: Group) => this.groups.set(g.id, g));
      } catch (e) {}
    }
  }

  private async setupPeer(displayName: string, collisionCount = 0) {
    const parts = (this.currentPeerId || '').split('-');
    const baseId = parts[0];
    const sessionBase = parts[1] || '0000';
    const generation = parts[2] || '1';
    const finalId = collisionCount > 0 ? `${baseId}-${sessionBase}-${generation}-${collisionCount}` : `${baseId}-${sessionBase}-${generation}`;
    
    // Update local state if we had to change the ID
    if (collisionCount > 0) {
      this.currentPeerId = finalId;
    }
    
    this.identity = { 
      classicalPublicKey: this.qIdentity!.classicalPublicKey,
      pqcPublicKey: this.qIdentity!.pqcPublicKey,
      identityBytes: this.qIdentity!.classicalPublicKey + this.qIdentity!.pqcPublicKey,
      displayName,
      id: finalId
    };

    if (this.peer) {
      try {
        this.peer.destroy();
      } catch (e) {}
    }

    if (this.signalingWatchdog) {
      clearInterval(this.signalingWatchdog);
    }

    const iceServers = [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun.services.mozilla.com' },
      { urls: 'stun:stun.cloudflare.com:3478' },
      { urls: 'stun:openrelay.metered.ca:80' },
      {
        urls: 'turn:openrelay.metered.ca:80',
        username: 'openrelayproject',
        credential: 'openrelayproject'
      },
      {
        urls: 'turn:openrelay.metered.ca:443',
        username: 'openrelayproject',
        credential: 'openrelayproject'
      }
    ];

    this.peer = new Peer(finalId, {
      config: { iceServers },
      debug: 1,
      secure: true
    });
    
    this.peer.on('open', async (openedId) => {
      console.log(`P2P Node Online: ${openedId}`);
      if (this.identity) this.identity.id = openedId;
      this.notifyStatus('info', 'Secure Node Online');
      await this.publishToDiscovery();
      
      // Start signaling watchdog
      if (this.signalingWatchdog) clearInterval(this.signalingWatchdog);
      this.signalingWatchdog = setInterval(() => {
        if (this.peer && (this.peer.disconnected || this.peer.destroyed)) {
           console.log("Watchdog: Signaling lost, reconnecting...");
           this.peer.reconnect();
        }
      }, 30000);
    });

    this.peer.on('disconnected', () => {
      this.notifyStatus('info', 'Signaling Disconnected. Reconnecting...');
      this.peer?.reconnect();
    });

    this.peer.on('error', (err: any) => {
      console.error('PeerJS error:', err);
      
      // Handle signaling loss
      if (err.type === 'network') {
        this.notifyStatus('warning', 'Signaling lost. Re-establishing link...');
        setTimeout(() => this.setupPeer(displayName, collisionCount), 3000);
        return;
      }

      // Handle ID collision (e.g. stale session from reload)
      if (err.type === 'unavailable-id' && collisionCount < 10) {
        console.warn(`ID ${finalId} is taken, retrying with incremented suffix...`);
        // Wait globally longer on deeper retries to let server heartbeat expire
        const delay = collisionCount > 2 ? 3000 : 800;
        setTimeout(() => this.setupPeer(displayName, collisionCount + 1), delay);
        return;
      }

      // Handle negotiation failures which often happen during signaling transitions
      if (err.message?.includes('Negotiation of connection') && collisionCount < 3) {
         console.warn("Negotiation failed, attempting re-setup...");
         setTimeout(() => this.setupPeer(displayName, collisionCount), 1000);
         return;
      }

      if (err.type === 'peer-unavailable') {
        this.notifyStatus('error', 'Target Peer not found. Check if ID is correct/online.');
      } else {
        this.notifyStatus('error', `Network: ${err.type}`);
      }
    });

    this.peer.on('connection', (conn) => {
      this.handleIncomingConnection(conn);
    });
  }

  private async getDiscoveryKeypair(name: string) {
    // Deterministic key for name discovery
    const seed = new TextEncoder().encode(`iroh-discovery-v3-${name.toLowerCase().trim()}`);
    const hash = await window.crypto.subtle.digest('SHA-256', seed);
    const seedBytes = new Uint8Array(hash);
    
    // Pkarr expects a 64-byte secretKey (seed + publicKey)
    // We can use Pkarr's own key generation for compatibility
    const keyPair = Pkarr.generateKeyPair(seedBytes);
    
    return { 
      publicKey: new Uint8Array(keyPair.publicKey), 
      privateKey: new Uint8Array(keyPair.secretKey) 
    };
  }

  async publishToDiscovery() {
    if (!this.identity || this.identity.displayName.length < 3) return;
    try {
      const name = this.identity.displayName;
      const { publicKey, privateKey } = await this.getDiscoveryKeypair(name);
      
      const ticket = this.currentPeerId!; 
      
      // Build DNS packet using Pkarr's EXPECTED structure
      const packet = {
        answers: [{
          type: 'TXT',
          name: '@',
          data: [ticket]
        }]
      };

      // Sign using Pkarr's helper
      // Use steady sequence number based on microseconds + small offset to handle rapid reloads/multiple tabs
      const seq = Math.floor(Date.now() * 1000) + Math.floor(Math.random() * 1000);
      const signedPacket = SignedPacket.fromPacket(
        { publicKey, secretKey: privateKey }, 
        packet as any, 
        { timestamp: seq as any }
      );

      const relays = [
        'https://relay.pkarr.org',
        'https://relay.orb.network',
        'https://pkarr.sh'
      ];

      let success = false;
      
      for (const relayUrl of relays) {
        try {
          const res = await Pkarr.relayPut(relayUrl, signedPacket);
          if (res.ok) {
            console.log(`Discovered as ${name} via ${relayUrl}`);
            success = true;
            break;
          } else if (res.status === 428) {
             console.warn(`Relay ${relayUrl} requires a newer sequence number (428).`);
          } else {
            console.warn(`Relay ${relayUrl} rejected publication: ${res.status}`);
          }
        } catch (err) {
          console.warn(`Failed to reach relay ${relayUrl}:`, err);
        }
      }
      
      if (!success) {
        this.notifyStatus('error', 'Discovery Relay Unavailable');
      }
    } catch (e) {
      console.error("Discovery publication failed", e);
    }
  }

  async searchByName(name: string): Promise<string | null> {
    try {
      this.notifyStatus('info', `Searching DHT for "${name}"...`);
      const { publicKey } = await this.getDiscoveryKeypair(name);
      
      const relays = [
        'https://relay.pkarr.org',
        'https://relay.orb.network',
        'https://pkarr.sh'
      ];

      let signedPacket: SignedPacket | null = null;
      
      for (const relayUrl of relays) {
        try {
          signedPacket = await Pkarr.relayGet(relayUrl, publicKey);
          if (signedPacket) break;
        } catch (err) {
          console.warn(`Query failed for relay ${relayUrl}:`, err);
        }
      }

      if (!signedPacket) {
        this.notifyStatus('error', 'Peer not found or discovery offline');
        return null;
      }

      // Extract the ticket from the TXT records
      const txtRecords = signedPacket.resourceRecords('@').filter(r => r.type === 'TXT');
      if (txtRecords.length > 0 && txtRecords[0].data && txtRecords[0].data[0]) {
        const ticket = txtRecords[0].data[0].toString();
        this.notifyStatus('info', `Resolved ${name} -> ${ticket.slice(0, 8)}...`);
        return ticket;
      }
      
      return null;
    } catch (e) {
      console.error("Discovery lookup failed", e);
      return null;
    }
  }

  private toZBase32(data: Uint8Array): string {
    return z32.encode(data);
  }

  reconnect() {
    if (this.peer && this.peer.disconnected) {
      this.peer.reconnect();
    } else if (!this.peer) {
      this.initialize(this.identity?.displayName || 'Node');
    }
  }

  public notifyStatus(type: 'info' | 'error' | 'warning', message: string) {
    if (this.onStatusCallback) {
      this.onStatusCallback(type, message);
    }
  }

  onStatus(callback: (type: 'info' | 'error' | 'warning', message: string) => void) {
    this.onStatusCallback = callback;
  }

  private async handleIncomingConnection(conn: DataConnection) {
    conn.on('open', () => {
      this.connections.set(conn.peer, conn);
    });

    conn.on('data', async (data: any) => {
      if (data.type === 'HELO') {
        console.log(`[Handshake] Received HELO from ${conn.peer}`);
        const { secret, ciphertext } = await deriveHybridSecret(
          this.qIdentity!, 
          data.classicalPublicKey, 
          data.pqcPublicKey, 
          false
        );
        this.secrets.set(conn.peer, secret);
        this.handshakeStatus.set(conn.peer, true);
        this.peerPks.set(conn.peer, { classical: data.classicalPublicKey, pqc: data.pqcPublicKey });
        
        // Responder sends HELO_ACK with Bob's PK and the CT for Alice's Kyber PK
        conn.send({ 
          type: 'HELO_ACK', 
          classicalPublicKey: this.identity!.classicalPublicKey,
          pqcCiphertext: ciphertext, 
          displayName: this.identity!.displayName
        });
        console.log(`[Handshake] Sent HELO_ACK to ${conn.peer}`);
        
        if (data.displayName) {
          this.peerMetadata.set(conn.peer, { displayName: data.displayName });
          this.persistMetadata();
        }

      } else if (data.type === 'GROUP_INVITE') {
        // ... handled in existing block ...
        const group: Group = data.group;
        this.groups.set(group.id, group);
        localStorage.setItem('nexus_groups', JSON.stringify(Array.from(this.groups.values())));
        if (this.onGroupUpdateCallback) {
          this.onGroupUpdateCallback(Array.from(this.groups.values()));
        }

      } else if (data.type === 'HELO_ACK') {
        console.log(`[Handshake] Received HELO_ACK from ${conn.peer}`);
        // Alice receives Bob's PK and the CT
        const { secret } = await deriveHybridSecret(
          this.qIdentity!, 
          data.classicalPublicKey, 
          data.pqcCiphertext, // Alice uses CT to decap
          true
        );
        this.secrets.set(conn.peer, secret);
        this.handshakeStatus.set(conn.peer, true);
        console.log(`[Handshake] Tunnel Secured with ${conn.peer}`);
        this.peerPks.set(conn.peer, { classical: data.classicalPublicKey, pqc: 'Encapsulated Session' });
        
        if (data.displayName) {
          this.peerMetadata.set(conn.peer, { displayName: data.displayName });
          this.persistMetadata();
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

  private persistMetadata() {
    const metadata = Object.fromEntries(this.peerMetadata);
    localStorage.setItem('nexus_metadata', JSON.stringify(metadata));
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
      console.error('Connection error:', err);
      this.notifyStatus('error', `Tunnel Failed: ${err.message || 'Network unreachable'}`);
      this.connections.delete(ticket);
    });

    conn.on('close', () => {
      this.notifyStatus('info', 'Tunnel Closed');
      this.connections.delete(ticket);
      this.handshakeStatus.delete(ticket);
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
    localStorage.setItem('nexus_groups', JSON.stringify(Array.from(this.groups.values())));
    
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
    return this.identity; 
  }
  getQuantumIdentity() { return this.qIdentity; }
  
  getPeerKeys(peerId: string) {
    return this.peerPks.get(peerId);
  }

  isHandshakeComplete(peerId: string) {
    return this.handshakeStatus.get(peerId) || false;
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
