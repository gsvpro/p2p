import Peer, { DataConnection } from 'peerjs';
import { generateIdentity, hashId, deriveSharedSecret, encryptData, decryptText, decryptData } from './crypto';
import { Identity, SecureMessage, FileTransfer } from '../types';
import { v4 as uuidv4 } from 'uuid';

const CHUNK_SIZE = 16384; // 16KB chunks for progress tracking

export class IrohManager {
  private peer: Peer | null = null;
  private identity: Identity | null = null;
  private connections: Map<string, DataConnection> = new Map();
  private secrets: Map<string, CryptoKey> = new Map();
  private transfers: Map<string, FileTransfer> = new Map();
  private fileChunks: Map<string, Uint8Array[]> = new Map();
  
  private onMessageCallback: ((msg: SecureMessage) => void) | null = null;
  private onTransferUpdateCallback: ((transfers: FileTransfer[]) => void) | null = null;

  async initialize(displayName: string) {
    const { publicKey, privateKey } = await generateIdentity();
    const id = await hashId(publicKey);
    
    this.identity = { publicKey, privateKey, id, displayName };
    this.peer = new Peer(id);
    
    this.peer.on('connection', (conn) => {
      this.handleIncomingConnection(conn);
    });
  }

  private async handleIncomingConnection(conn: DataConnection) {
    conn.on('open', () => {
      this.connections.set(conn.peer, conn);
    });

    conn.on('data', async (data: any) => {
      let secret = this.secrets.get(conn.peer);
      
      if (data.type === 'HELO') {
        const sharedSecret = await deriveSharedSecret(this.identity!.privateKey!, data.publicKey);
        this.secrets.set(conn.peer, sharedSecret);
        conn.send({ type: 'HELO_ACK', publicKey: this.identity!.publicKey });
      } else if (data.type === 'HELO_ACK') {
        const sharedSecret = await deriveSharedSecret(this.identity!.privateKey!, data.publicKey);
        this.secrets.set(conn.peer, sharedSecret);
      } else if (data.encrypted) {
        secret = this.secrets.get(conn.peer);
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
    if (!this.peer || this.connections.has(ticket)) return;
    const conn = this.peer.connect(ticket);
    conn.on('open', () => {
      this.connections.set(ticket, conn);
      conn.send({ type: 'HELO', publicKey: this.identity!.publicKey });
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

  getIdentity() { return this.identity; }
  getConnectedPeers() { return Array.from(this.connections.keys()); }
}

export const iroh = new IrohManager();
