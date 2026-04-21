# CipherNexus P2P

A secure, end-to-end encrypted P2P messaging and file transfer platform using Nostr for signaling and WebRTC for direct peer-to-peer communication. Named after Iroh from Legend of Korra - the quantum bridge bending uncle who connects worlds.

## Features

- **End-to-End Encryption** - Hybrid post-quantum cryptography (ML-KEM + ECDH) for secure communication
- **Direct P2P** - Files and messages go directly between devices via WebRTC tunnels
- **No Account Required** - Identity based on cryptographic keys, not email/phone
- **File Transfer** - Secure file sharing up to any size via chunked P2P streaming
- **Groups** - Encrypted group chats with multiple participants
- **Nostr Integration** - Uses Nostr for peer discovery and WebRTC signaling
- **Mobile Ready** - Works on iOS and Android browsers

## Architecture

```
┌─────────┐    Nostr (signaling)    ┌─────────┐
│  Node A │◄─────────────────────►│  Node B │
│ (iPhone │                          │(Desktop│
│        │    WebRTC (data)         │        )
└─────────┘◄─────────────────────►└────────┘
```

1. **Discovery** - Peers find each other via Nostr relays using npub/petnames
2. **Handshake** - Hybrid key exchange (ML-KEM-1024 + ECDH P-256) establishes shared secret
3. **Tunnel** - Direct WebRTC data channel for encrypted messages/files
4. **Transfer** - Files chunked and encrypted with AES-256-GCM

## Getting Started

### Prerequisites

- Node.js 18+
- npm or pnpm

### Install & Run

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open http://localhost:3000 to use the app.

### Usage

1. Open the app in two browsers or on different devices
2. Share your node ticket (npub) with the other peer
3. Enter the peer's npub to connect
4. Once tunnel is established, send messages and files

## Security

### Cryptography

- **Key Exchange**: Hybrid ML-KEM-1024 (post-quantum) + ECDH P-256 (classical)
- **Message Encryption**: AES-256-GCM
- **Signatures**: Ed25519 for Nostr events

### Threat Model

- Forward secrecy via ephemeral session keys
- Post-quantum resistance via ML-KEM
- No metadata revelation (relays see only encrypted blobs)

## Tech Stack

- **Frontend**: React + TypeScript + TailwindCSS
- **Crypto**: Web Crypto API + ML-KEM-1024
- **Signaling**: Nostr (NIP-26, NIP-17)
- **P2P**: Simple-WebRTC
- **Build**: Vite

## License

MIT