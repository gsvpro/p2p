import * as dnsPacket from 'dns-packet';
import bencode from 'bencode';
import Pkarr, { z32, SignedPacket } from 'pkarr';
import { generateIdentity, hashId, deriveHybridSecret, encryptData, decryptText, decryptData, QuantumIdentity, importIdentity, exportIdentity, b64encode } from './crypto';
import { Identity, SecureMessage, FileTransfer, Group } from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as ed from '@noble/ed25519';
import { sha512 } from 'js-sha512';
import SimplePeer from 'simple-peer';
import { SimplePool, getPublicKey, getEventHash, nip19, finalizeEvent } from 'nostr-tools';

const CHUNK_SIZE = 16384;
const NOSTR_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.snort.social',
  'wss://relay.primal.net'
];

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
  private identity: Identity | null = null;
  private qIdentity: QuantumIdentity | null = null;
  private connections: Map<string, any> = new Map();
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
  
  private nostrPool = new SimplePool();
  private currentPeerId: string | null = null;
  private signKey: Uint8Array | null = null;
  private isSignalingSettled = false;
  private activeSubscriptions: Set<string> = new Set();

  async initialize(displayName: string) {
    const savedIdentity = localStorage.getItem('nexus_identity');
    if (savedIdentity) {
      try {
        this.qIdentity = await importIdentity(savedIdentity);
      } catch (e) {
        this.qIdentity = await generateIdentity();
      }
    } else {
      this.qIdentity = await generateIdentity();
      const serialized = await exportIdentity(this.qIdentity);
      localStorage.setItem('nexus_identity', serialized);
    }

    const id = await hashId(this.qIdentity.classicalPublicKey);
    this.currentPeerId = id;
    this.signKey = new Uint8Array(id.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
    
    await this.setupPeer(displayName);

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

  private async setupPeer(displayName: string) {
    this.identity = { 
      classicalPublicKey: this.qIdentity!.classicalPublicKey,
      pqcPublicKey: this.qIdentity!.pqcPublicKey,
      identityBytes: this.qIdentity!.classicalPublicKey + this.qIdentity!.pqcPublicKey,
      displayName,
      id: this.currentPeerId!
    };

    this.isSignalingSettled = false;
    this.notifyStatus('info', 'Connecting to Global Relay Nodes...');
    this.listenOnNostr(this.currentPeerId!);

    setTimeout(async () => {
       this.isSignalingSettled = true;
       this.notifyStatus('info', 'Secure Node Online (Decentralized)');
       await this.publishToDiscovery();
    }, 2000);
  }

  private async getSignalingSecret(topicId: string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(`iroh-signal-v3-${topicId}`);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return await crypto.subtle.importKey(
      'raw', 
      new Uint8Array(hash), 
      { name: 'AES-GCM', length: 256 }, 
      false, 
      ['encrypt', 'decrypt']
    );
  }

  private async listenOnNostr(topicId: string) {
    if (this.activeSubscriptions.has(topicId)) return;
    this.activeSubscriptions.add(topicId);

    const secret = await this.getSignalingSecret(topicId);
    
    this.nostrPool.subscribeMany(
      NOSTR_RELAYS,
      { kinds: [29001], '#t': [topicId], since: Math.floor(Date.now() / 1000) } as any,
      {
        onevent: async (event) => {
          try {
            const iv = event.tags.find(t => t[0] === 'iv')?.[1];
            if (!iv) return;
            const decrypted = await decryptText(secret, event.content, iv);
            const signal = JSON.parse(decrypted);
            
            if (signal.senderId === this.currentPeerId) return;

            if (signal.type === 'offer') {
              this.handleNostrOffer(topicId, signal);
            } else if (signal.type === 'answer' || signal.type === 'candidate') {
              const conn = this.connections.get(signal.senderId);
              if (conn) conn.signal(signal.sdp);
            }
          } catch (e) {}
        }
      }
    );
  }

  private async handleNostrOffer(topicId: string, signal: any) {
    const peerId = signal.senderId;
    if (this.connections.has(peerId)) return;

    this.notifyStatus('info', `P2P Handshake from ${peerId.slice(0, 8)}...`);
    
    // @ts-ignore
    const peer = new SimplePeer({
      initiator: false,
      trickle: true,
      config: { iceServers: this.getIceServers() }
    });

    this.setupSimplePeer(peer, peerId, topicId);
    peer.signal(signal.sdp);
  }

  private getIceServers() {
    return [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun.services.mozilla.com' },
      { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' },
      { urls: 'turn:openrelay.metered.ca:443', username: 'openrelayproject', credential: 'openrelayproject' }
    ];
  }

  private async sendNostrSignal(topicId: string, payload: any) {
    const secret = await this.getSignalingSecret(topicId);
    const { ciphertext, iv } = await encryptData(secret, JSON.stringify(payload));
    
    const unsignedEvent = {
      kind: 29001,
      pubkey: getPublicKey(this.signKey!),
      created_at: Math.floor(Date.now() / 1000),
      tags: [['t', topicId], ['iv', iv]],
      content: ciphertext
    };

    const event = finalizeEvent(unsignedEvent, this.signKey!);
    this.nostrPool.publish(NOSTR_RELAYS, event);
  }

  private setupSimplePeer(peer: any, peerId: string, topicId: string) {
    peer.on('signal', (data: any) => {
      this.sendNostrSignal(topicId, {
        senderId: this.currentPeerId,
        type: data.type === 'offer' ? 'offer' : (data.candidate ? 'candidate' : 'answer'),
        sdp: data
      });
    });

    peer.on('connect', () => {
      this.connections.set(peerId, peer);
      this.notifyStatus('info', `Tunnel Established: Node_${peerId.slice(0, 4)}`);
      
      peer.send(JSON.stringify({ 
        type: 'HELO', 
        classicalPublicKey: this.identity!.classicalPublicKey,
        pqcPublicKey: this.identity!.pqcPublicKey,
        displayName: this.identity!.displayName
      }));
    });

    peer.on('data', async (data: any) => {
       const msg = JSON.parse(data.toString());
       this.processIncomingMessage(peerId, msg);
    });

    peer.on('close', () => {
      this.connections.delete(peerId);
      this.handshakeStatus.delete(peerId);
      this.notifyStatus('info', 'Tunnel Closed');
    });

    peer.on('error', (err: any) => {
      this.connections.delete(peerId);
      this.notifyStatus('error', `Tunnel Failed: ${err.message || 'Network unreachable'}`);
    });
  }

  private async processIncomingMessage(peerId: string, data: any) {
    if (data.type === 'HELO') {
      const { secret, ciphertext } = await deriveHybridSecret(
        this.qIdentity!, 
        data.classicalPublicKey, 
        data.pqcPublicKey, 
        false
      );
      this.secrets.set(peerId, secret);
      this.handshakeStatus.set(peerId, true);
      this.peerPks.set(peerId, { classical: data.classicalPublicKey, pqc: data.pqcPublicKey });
      
      const conn = this.connections.get(peerId);
      conn?.send(JSON.stringify({ 
        type: 'HELO_ACK', 
        classicalPublicKey: this.identity!.classicalPublicKey,
        pqcCiphertext: ciphertext, 
        displayName: this.identity!.displayName
      }));
      
      if (data.displayName) {
        this.peerMetadata.set(peerId, { displayName: data.displayName });
        this.persistMetadata();
      }

    } else if (data.type === 'HELO_ACK') {
      const { secret } = await deriveHybridSecret(
        this.qIdentity!, 
        data.classicalPublicKey, 
        data.pqcCiphertext,
        true
      );
      this.secrets.set(peerId, secret);
      this.handshakeStatus.set(peerId, true);
      this.peerPks.set(peerId, { classical: data.classicalPublicKey, pqc: 'Encapsulated Session' });
      
      if (data.displayName) {
        this.peerMetadata.set(peerId, { displayName: data.displayName });
        this.persistMetadata();
      }

    } else if (data.encrypted) {
      const secret = this.secrets.get(peerId);
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
          await this.handleFileChunk(peerId, data, secret);
        } else if (data.type === 'GROUP_INVITE') {
           const group: Group = data.group;
           this.groups.set(group.id, group);
           localStorage.setItem('nexus_groups', JSON.stringify(Array.from(this.groups.values())));
           if (this.onGroupUpdateCallback) {
             this.onGroupUpdateCallback(Array.from(this.groups.values()));
           }
           this.notifyStatus('info', `New Group: ${group.name}`);
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
  }

  async connectByTicket(ticket: string) {
    if (this.connections.has(ticket)) return;
    this.notifyStatus('info', `Attempting Tunnel via Nostr Relay...`);
    this.listenOnNostr(ticket);

    // @ts-ignore
    const peer = new SimplePeer({
      initiator: true,
      trickle: true,
      config: { iceServers: this.getIceServers() }
    });

    this.setupSimplePeer(peer, ticket, ticket);
  }

  private async getDiscoveryKeypair(name: string) {
    const seed = new TextEncoder().encode(`iroh-discovery-v3-${name.toLowerCase().trim()}`);
    const hash = await window.crypto.subtle.digest('SHA-256', seed);
    const keyPair = Pkarr.generateKeyPair(new Uint8Array(hash));
    return { publicKey: new Uint8Array(keyPair.publicKey), privateKey: new Uint8Array(keyPair.secretKey) };
  }

  async publishToDiscovery() {
    if (!this.identity || this.identity.displayName.length < 3) return;
    try {
      const name = this.identity.displayName;
      const { publicKey, privateKey } = await this.getDiscoveryKeypair(name);
      const packet = { answers: [{ type: 'TXT', name: '@', data: [this.currentPeerId!] }] };
      const seq = Math.floor(Date.now() * 1000);
      const signedPacket = SignedPacket.fromPacket({ publicKey, secretKey: privateKey }, packet as any, { timestamp: seq as any });
      const relays = ['https://relay.pkarr.org', 'https://pkarr.sh'];
      for (const relayUrl of relays) {
        try { await Pkarr.relayPut(relayUrl, signedPacket); } catch (e) {}
      }
    } catch (e) {}
  }

  async searchByName(name: string): Promise<string | null> {
    try {
      this.notifyStatus('info', `Searching DHT for "${name}"...`);
      const { publicKey } = await this.getDiscoveryKeypair(name);
      const relays = ['https://relay.pkarr.org', 'https://pkarr.sh'];
      let signedPacket: SignedPacket | null = null;
      for (const relayUrl of relays) {
        try {
          signedPacket = await Pkarr.relayGet(relayUrl, publicKey);
          if (signedPacket) break;
        } catch (err) {}
      }
      if (!signedPacket) return null;
      const txtRecords = signedPacket.resourceRecords('@').filter(r => r.type === 'TXT');
      if (txtRecords.length > 0 && txtRecords[0].data && txtRecords[0].data[0]) {
        return txtRecords[0].data[0].toString();
      }
      return null;
    } catch (e) { return null; }
  }

  reconnect() {
    this.initialize(this.identity?.displayName || 'Node');
  }

  public notifyStatus(type: 'info' | 'error' | 'warning', message: string) {
    if (this.onStatusCallback) this.onStatusCallback(type, message);
  }

  onStatus(callback: (type: 'info' | 'error' | 'warning', message: string) => void) {
    this.onStatusCallback = callback;
  }

  private persistMetadata() {
    localStorage.setItem('nexus_metadata', JSON.stringify(Object.fromEntries(this.peerMetadata)));
  }

  private async handleFileChunk(peerId: string, data: any, secret: CryptoKey) {
    let transfer = this.transfers.get(data.transferId);
    let chunks = this.fileChunks.get(data.transferId);
    if (!transfer) {
      transfer = { id: data.transferId, name: data.fileName, size: data.totalSize, progress: 0, type: 'download', status: 'active', peerId };
      this.transfers.set(data.transferId, transfer);
      chunks = [];
      this.fileChunks.set(data.transferId, chunks);
    }
    const chunk = await decryptData(secret, data.content, data.iv);
    chunks!.push(chunk);
    transfer.progress += chunk.length;
    if (transfer.progress >= transfer.size) {
      transfer.status = 'completed';
      const blob = new Blob(chunks, { type: 'application/octet-stream' });
      transfer.downloadUrl = URL.createObjectURL(blob);
    }
    this.notifyTransferUpdate();
  }

  private notifyTransferUpdate() {
    if (this.onTransferUpdateCallback) this.onTransferUpdateCallback(Array.from(this.transfers.values()));
  }

  onTransferUpdate(callback: (transfers: FileTransfer[]) => void) { this.onTransferUpdateCallback = callback; }
  onGroupUpdate(callback: (groups: Group[]) => void) { this.onGroupUpdateCallback = callback; }

  async createGroup(name: string, members: string[]) {
    const group: Group = { id: uuidv4(), name, members: [...new Set([...members, this.identity!.id])], createdAt: Date.now() };
    this.groups.set(group.id, group);
    localStorage.setItem('nexus_groups', JSON.stringify(Array.from(this.groups.values())));
    if (this.onGroupUpdateCallback) this.onGroupUpdateCallback(Array.from(this.groups.values()));
    members.forEach(m => {
      const conn = this.connections.get(m);
      if (conn) conn.send(JSON.stringify({ type: 'GROUP_INVITE', group }));
    });
    return group;
  }

  async sendGroupMessage(groupId: string, text: string, options: { ephemeral?: boolean } = {}) {
    const group = this.groups.get(groupId);
    if (!group) return;
    const msgId = uuidv4();
    const timestamp = Date.now();
    const expiresAt = options.ephemeral ? timestamp + 60000 : undefined;
    group.members.forEach(async (memberId) => {
      if (memberId === this.identity?.id) return;
      const conn = this.connections.get(memberId);
      const secret = this.secrets.get(memberId);
      if (conn && secret) {
        const { ciphertext, iv } = await encryptData(secret, text);
        conn.send(JSON.stringify({ id: msgId, senderId: this.identity!.id, receiverId: memberId, groupId, type: 'text', content: ciphertext, iv, timestamp, expiresAt, encrypted: true }));
      }
    });
    return { id: msgId, senderId: this.identity!.id, receiverId: groupId, groupId, type: 'text' as const, content: text, iv: '', timestamp, expiresAt };
  }

  async sendMessage(peerId: string, text: string, options: { ephemeral?: boolean } = {}) {
    const conn = this.connections.get(peerId);
    const secret = this.secrets.get(peerId);
    if (!conn || !secret) return null;
    const { ciphertext, iv } = await encryptData(secret, text);
    const msg: SecureMessage = { id: uuidv4(), senderId: this.identity!.id, receiverId: peerId, type: 'text', content: ciphertext, iv, timestamp: Date.now(), expiresAt: options.ephemeral ? Date.now() + 60000 : undefined };
    conn.send(JSON.stringify({ ...msg, encrypted: true }));
    return { ...msg, content: text };
  }

  async sendFile(peerId: string, file: File) {
    const conn = this.connections.get(peerId);
    const secret = this.secrets.get(peerId);
    if (!conn || !secret) return;
    const transferId = uuidv4();
    const transfer: FileTransfer = { id: transferId, name: file.name, size: file.size, progress: 0, type: 'upload', status: 'active', peerId };
    this.transfers.set(transferId, transfer);
    const reader = new FileReader();
    let offset = 0;
    const readNext = () => { reader.readAsArrayBuffer(file.slice(offset, offset + CHUNK_SIZE)); };
    reader.onload = async (e) => {
      const { ciphertext, iv } = await encryptData(secret, new Uint8Array(e.target?.result as ArrayBuffer));
      conn.send(JSON.stringify({ encrypted: true, type: 'file_chunk', transferId, fileName: file.name, totalSize: file.size, content: ciphertext, iv }));
      offset += (e.target?.result as ArrayBuffer).byteLength;
      transfer.progress = offset;
      this.notifyTransferUpdate();
      if (offset < file.size) readNext();
      else { transfer.status = 'completed'; this.notifyTransferUpdate(); }
    };
    readNext();
  }

  async sendReaction(peerId: string, messageId: string, emoji: string) {
    const conn = this.connections.get(peerId);
    const secret = this.secrets.get(peerId);
    if (!conn || !secret) return;
    const { ciphertext, iv } = await encryptData(secret, JSON.stringify({ targetMessageId: messageId, emoji }));
    const msg: SecureMessage = { id: uuidv4(), senderId: this.identity!.id, receiverId: peerId, type: 'reaction', content: ciphertext, iv, timestamp: Date.now(), targetMessageId: messageId };
    conn.send(JSON.stringify({ ...msg, encrypted: true, type: 'reaction' }));
    return { ...msg, content: emoji };
  }

  onMessage(callback: (msg: SecureMessage) => void) { this.onMessageCallback = callback; }
  getIdentity() { return this.identity; }
  getQuantumIdentity() { return this.qIdentity; }
  getPeerKeys(peerId: string) { return this.peerPks.get(peerId); }
  isHandshakeComplete(peerId: string) { return this.handshakeStatus.get(peerId) || false; }
  getPeerName(peerId: string) { return this.peerMetadata.get(peerId)?.displayName; }
  getGroups() { return Array.from(this.groups.values()); }
  setDisplayName(name: string) {
    if (this.identity) {
      this.identity.displayName = name;
      localStorage.setItem('nexus_name', name);
      this.publishToDiscovery();
    }
  }
  getConnectedPeers() { return Array.from(this.connections.keys()).filter(k => this.connections.get(k)?.connected); }
}

export const iroh = new IrohManager();
