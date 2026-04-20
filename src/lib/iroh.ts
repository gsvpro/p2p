import * as dnsPacket from 'dns-packet';
import bencode from 'bencode';
import Pkarr, { z32, SignedPacket } from 'pkarr';
import { generateIdentity, hashId, deriveHybridSecret, encryptData, decryptText, decryptData, QuantumIdentity, importIdentity, exportIdentity, b64encode } from './crypto';
import { Identity, SecureMessage, FileTransfer, Group } from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as ed from '@noble/ed25519';
import { sha512 } from 'js-sha512';
import SimplePeer from 'simple-peer/simplepeer.min.js';
import { SimplePool, getPublicKey, getEventHash, nip19, finalizeEvent } from 'nostr-tools';

const CHUNK_SIZE = 16384;
let DEFAULT_NOSTR_RELAYS = [
  'wss://nos.lol',
  'wss://relay.snort.social',
  'wss://relay.nostr.band',
  'wss://nostr.bitcoiner.social',
  'wss://relay.current.fyi'
];

let NOSTR_RELAYS = [...DEFAULT_NOSTR_RELAYS];

const savedRelays = localStorage.getItem('nexus_custom_relays');
if (savedRelays) {
  try {
    const parsed = JSON.parse(savedRelays);
    if (Array.isArray(parsed) && parsed.length > 0) {
      NOSTR_RELAYS = parsed;
    }
  } catch (e) {}
}

const PKARR_RELAYS = [
  'https://relay.pkarr.org',
  'https://dht.iroh.computer',
  'https://pkarr.iroh.computer'
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
  private onSignalStatusCallback: ((count: number) => void) | null = null;
  
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

    // Force reset stale relays if version mismatch
    const storedVer = localStorage.getItem('nexus_iroh_ver');
    if (storedVer !== '2.5.0') {
      localStorage.removeItem('nexus_custom_relays');
      localStorage.setItem('nexus_iroh_ver', '2.5.0');
      // Force reload to apply clean state
      window.location.reload();
      return;
    }

    const id = await hashId(this.qIdentity.classicalPublicKey);
    this.currentPeerId = id;
    
    // Step 1: Force early relay connections
    NOSTR_RELAYS.forEach(url => {
      try {
        (this.nostrPool as any).ensureRelay(url).catch(() => {});
      } catch (e) {}
    });

    // Mesh Status Logic for nostr-tools v2
    setInterval(() => {
      let active = 0;
      try {
        const pool = (this.nostrPool as any);
        // Direct access to the relay Map in nostr-tools v2 SimplePool
        const relayMap = pool.relays || pool._relays;
        if (relayMap) {
          relayMap.forEach((relay: any) => {
            // Check for websocket readyState 1 (OPEN) or pool-level status 1
            if (relay && (relay.status === 1 || (relay.ws && relay.ws.readyState === 1))) {
              active++;
            }
          });
        }
      } catch (e) {}
      this.onSignalStatusCallback?.(active);
    }, 3000);
    
    // Nostr needs a 32-byte private key. We derive it from the identity.
    const signSeed = new TextEncoder().encode(`nostr-sig-v2-${this.qIdentity.classicalPublicKey}`);
    const signHash = await window.crypto.subtle.digest('SHA-256', signSeed);
    this.signKey = new Uint8Array(signHash);
    
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
    if (!topicId || this.activeSubscriptions.has(topicId)) return;
    this.activeSubscriptions.add(topicId);

    const secret = await this.getSignalingSecret(topicId);
    console.debug(`[Nostr] Subscribing to topic: ${topicId.slice(0, 8)}...`);
    
    // Using Kind 20000 (Ephemeral Signaling) - Standard and less filtered
    const filters = [{ 
      kinds: [20000], 
      '#t': [topicId]
    }];

    // Individual subscriptions per relay for maximum reliability
    NOSTR_RELAYS.forEach(url => {
      try {
        const pool = (this.nostrPool as any);
        pool.subscribeMany(
          [url],
          filters,
          {
            onevent: async (event: any) => {
              try {
                const iv = event.tags.find((t: any) => t[0] === 'iv')?.[1];
                if (!iv) return;
                const decrypted = await decryptText(secret, event.content, iv);
                const signal = JSON.parse(decrypted);
                
                if (signal.senderId === this.currentPeerId) return;
                console.debug(`[Nostr] Mesh IN on ${url}: ${signal.type}`);

                if (signal.type === 'offer') {
                  this.handleNostrOffer(topicId, signal);
                } else if (signal.type === 'answer' || signal.type === 'candidate') {
                  const conn = this.connections.get(signal.senderId);
                  if (conn) conn.signal(signal.sdp);
                }
              } catch (e) {}
            },
            oneose: () => {
              console.debug(`[Nostr] Sub Settled on ${url}`);
            }
          }
        );
      } catch (e) {
        console.warn(`Mesh Sub failed on ${url}:`, e);
      }
    });

  }

  private async handleNostrOffer(topicId: string, signal: any) {
    const peerId = signal.senderId;
    if (this.connections.has(peerId)) return;

    this.notifyStatus('info', `P2P Handshake from ${peerId.slice(0, 8)}...`);
    
    // @ts-ignore
    const peer = new SimplePeer({
      initiator: false,
      trickle: false,
      config: { iceServers: this.getIceServers() }
    });

    this.setupSimplePeer(peer, peerId, topicId);
    peer.signal(signal.sdp);
  }

  private getIceServers() {
    return [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun.cloudflare.com:3478' },
      { urls: 'stun:stun.services.mozilla.com' },
      { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' },
      { urls: 'turn:openrelay.metered.ca:443', username: 'openrelayproject', credential: 'openrelayproject' }
    ];
  }

  private async sendNostrSignal(topicId: string, payload: any) {
    if (!this.signKey || this.signKey.length !== 32) return;

    const secret = await this.getSignalingSecret(topicId);
    const { ciphertext, iv } = await encryptData(secret, JSON.stringify(payload));
    
    const unsignedEvent = {
      kind: 20000, // Ephemeral Signaling Kind
      pubkey: getPublicKey(this.signKey!),
      created_at: Math.floor(Date.now() / 1000),
      tags: [['t', topicId], ['iv', iv]],
      content: ciphertext
    };

    const event = finalizeEvent(unsignedEvent, this.signKey!);
    console.debug(`[Nostr] Signal OUT: ${payload.type}`);
    
    // Explicit publish to each relay. 
    // We don't await individual publishes to avoid blocking, 
    // but the pool handles the push in the background.
    NOSTR_RELAYS.forEach(url => {
      try {
        this.nostrPool.publish([url], event);
      } catch (e) {
        console.warn(`[Nostr] Publish failed on ${url}:`, e);
      }
    });
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
      trickle: false,
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
      const seq = Date.now();
      const signedPacket = SignedPacket.fromPacket({ publicKey, secretKey: privateKey }, packet as any, { seq: BigInt(seq) } as any);
      const bytes = signedPacket.bytes();
      
      let successCount = 0;
      for (const relayUrl of PKARR_RELAYS) {
        try {
          const res = await fetch(`${relayUrl}/${z32.encode(publicKey)}`, {
            method: 'PUT',
            body: bytes,
            mode: 'cors',
            headers: { 'Content-Type': 'application/octet-stream' }
          });
          if (res.ok) {
            successCount++;
            console.debug(`Identity published to Pkarr node: ${relayUrl}`);
          } else {
            console.warn(`Pkarr relay ${relayUrl} returned ${res.status}`);
          }
        } catch (e) {
          console.warn(`Failed to publish to Pkarr node ${relayUrl}:`, e);
        }
      }
      if (successCount > 0) {
        this.notifyStatus('info', `Node Discovered via ${successCount} DHT Relays`);
      }
      
      // Parallel layer: Nostr Announcement
      await this.publishToNostrDiscovery(name);
    } catch (e) {}
  }

  private async publishToNostrDiscovery(name: string) {
    if (!this.nostrPool || !this.signKey) return;
    const topic = `nexus_v2_discovery_${name.toLowerCase().trim()}`;
    const announcement = { type: 'announcement', peerId: this.currentPeerId, name, timestamp: Date.now() };
    const secret = await this.getSignalingSecret(topic);
    const { ciphertext, iv } = await encryptData(secret, JSON.stringify(announcement));
    
    const event = {
      kind: 22242,
      pubkey: getPublicKey(this.signKey),
      created_at: Math.floor(Date.now() / 1000),
      tags: [['t', topic], ['iv', iv]],
      content: ciphertext
    };
    const signed = finalizeEvent(event, this.signKey);
    await Promise.all(NOSTR_RELAYS.map(r => (this.nostrPool as any).publish(r, signed).catch(() => {})));
  }

  async searchByName(name: string): Promise<string | null> {
    try {
      this.notifyStatus('info', `Searching Mesh for "${name}"...`);
      
      // Parallel search
      const pkarrTask = this.searchByNamePkarr(name);
      const nostrTask = this.searchByNameNostr(name);
      
      const result = await Promise.race([pkarrTask, nostrTask]);
      if (result) return result;
      
      // If race didn't finish with a result, wait for both for a moment
      const results = await Promise.all([pkarrTask, nostrTask]);
      return results.find(r => r !== null) || null;
    } catch (e) {
      return null;
    }
  }

  private async searchByNameNostr(name: string): Promise<string | null> {
    if (!this.nostrPool) return null;
    const topic = `nexus_v2_discovery_${name.toLowerCase().trim()}`;
    const secret = await this.getSignalingSecret(topic);
    
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        sub.close();
        resolve(null);
      }, 5000);

      const filter = [{ kinds: [22242], '#t': [topic], limit: 5 }];
      const sub = (this.nostrPool as any).subscribeMany(NOSTR_RELAYS, filter, {
        onevent: async (event: any) => {
          try {
            const iv = event.tags.find((t: any) => t[0] === 'iv')?.[1];
            if (!iv) return;
            const decrypted = await decryptText(secret, event.content, iv);
            const data = JSON.parse(decrypted);
            if (data.type === 'announcement' && data.peerId) {
              clearTimeout(timeout);
              sub.close();
              resolve(data.peerId);
            }
          } catch (e) {}
        },
        oneose: () => {
          // Keep searching for a bit longer even after EOSE
        }
      });
    });
  }

  private async searchByNamePkarr(name: string): Promise<string | null> {
    try {
      const { publicKey } = await this.getDiscoveryKeypair(name);
      let signedPacket: SignedPacket | null = null;
      
      for (const relayUrl of PKARR_RELAYS) {
        try {
          const response = await fetch(`${relayUrl}/${z32.encode(publicKey)}`, {
            method: 'GET',
            mode: 'cors',
            credentials: 'omit'
          });
          
          if (!response.ok) continue;
          
          const buffer = await response.arrayBuffer();
          signedPacket = SignedPacket.fromBytes(publicKey, new Uint8Array(buffer));
          if (signedPacket) {
             console.debug(`Identity found via Pkarr node: ${relayUrl}`);
             break;
          }
        } catch (err) {
          // Silent catch for Pkarr failures
        }
      }
      if (!signedPacket) return null;
      const txtRecords = signedPacket.resourceRecords('@').filter(r => r.type === 'TXT');
      if (txtRecords.length > 0 && txtRecords[0].data && txtRecords[0].data[0]) {
        return txtRecords[0].data[0].toString();
      }
    } catch (e) {}
    return null;
  }

  async reconnect() {
    this.nostrPool.close(NOSTR_RELAYS);
    this.activeSubscriptions.clear();
    this.isSignalingSettled = false;
    this.initialize(this.identity?.displayName || 'Node');
  }

  public notifyStatus(type: 'info' | 'error' | 'warning', message: string) {
    if (this.onStatusCallback) this.onStatusCallback(type, message);
  }

  onStatus(callback: (type: 'info' | 'error' | 'warning', message: string) => void) {
    this.onStatusCallback = callback;
  }

  onSignalStatus(callback: (count: number) => void) {
    this.onSignalStatusCallback = callback;
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
  
  getRelays() {
    return NOSTR_RELAYS;
  }

  updateRelays(relays: string[]) {
    if (!Array.isArray(relays) || relays.length === 0) return;
    NOSTR_RELAYS = relays;
    localStorage.setItem('nexus_custom_relays', JSON.stringify(relays));
    this.notifyStatus('info', 'Relay list updated. Re-initializing...');
    this.reconnect();
  }

  resetRelays() {
    NOSTR_RELAYS = [...DEFAULT_NOSTR_RELAYS];
    localStorage.removeItem('nexus_custom_relays');
    this.notifyStatus('info', 'Relays reset to default.');
    this.reconnect();
  }

  getConnectedPeers() { return Array.from(this.connections.keys()).filter(k => this.connections.get(k)?.connected); }
}

export const iroh = new IrohManager();
