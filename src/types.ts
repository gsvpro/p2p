export type MessageType = 'text' | 'file' | 'system' | 'reaction';

export interface Identity {
  classicalPublicKey: string; // Base64
  pqcPublicKey: string; // Base64
  identityBytes: string; // Combined hash for Node ID
  displayName: string;
  id: string;
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
  groupId?: string; // Target group if any
  type: MessageType;
  content: string; // Encrypted Base64 or JSON
  iv: string; // Base64
  timestamp: number;
  fileName?: string;
  fileSize?: number;
  expiresAt?: number;
  reactions?: Record<string, string[]>; // emoji -> list of userIds
  targetMessageId?: string; // For reactions
  downloadUrl?: string; // For file transfers
}

export interface Group {
  id: string;
  name: string;
  members: string[]; // List of Node IDs
  createdAt: number;
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
