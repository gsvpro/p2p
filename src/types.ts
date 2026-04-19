export type MessageType = 'text' | 'file' | 'system' | 'reaction';

export interface Identity {
  publicKey: string; // Base64
  privateKey?: CryptoKey;
  id: string; // Node ID
  displayName: string;
}

export interface PeerInfo {
  id: string;
  publicKey: string;
  displayName: string;
  lastSeen: number;
  online: boolean;
}

export interface Reaction {
  emoji: string;
  senderId: string;
}

export interface SecureMessage {
  id: string;
  senderId: string;
  receiverId: string;
  type: MessageType;
  content: string; // Encrypted Base64 or JSON
  iv: string; // Base64
  timestamp: number;
  fileName?: string;
  fileSize?: number;
  expiresAt?: number;
  reactions?: Record<string, string[]>; // emoji -> list of userIds
  targetMessageId?: string; // For reactions
}

export interface FileTransfer {
  id: string;
  name: string;
  size: number;
  progress: number;
  type: 'upload' | 'download';
  status: 'active' | 'completed' | 'failed';
  peerId: string;
  downloadUrl?: string;
}

export interface ChatSession {
  peerId: string;
  messages: SecureMessage[];
  sharedSecret?: CryptoKey;
}
