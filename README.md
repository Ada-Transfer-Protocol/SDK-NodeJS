# AdaTP Node.js SDK

A robust, type-safe Node.js client for the Ada Transport Protocol (AdaTP). This SDK provides a simple API to connect to AdaTP servers, perform secure handshakes, and exchange confidential messages.

## Features

- **Secure Handshake**: Full implementation of the AdaTP handshake using X25519 key exchange and HKDF key derivation.
- **End-to-End Encryption**: All messages after handshake are encrypted using AES-256-GCM.
- **Type-Safe**: Written in TypeScript with complete type definitions.
- **Protocol Compliant**: Fully compatible with the official AdaTP Rust server.

## Installation

```bash
npm install adatp-sdk
# or locally
npm install ./path/to/adatp/sdks/nodejs
```

*Note: This package requires Node.js v16+ for native crypto support.*

## Usage

### Basic Connection

```typescript
import { AdaTPClient } from 'adatp-sdk';

async function main() {
    // Initialize client connecting to localhost:8443
    const client = new AdaTPClient('127.0.0.1', 8443);

    try {
        console.log("Connecting...");
        // Connects and performs the secure handshake automatically
        await client.connect();
        
        console.log("Secure session established!");

        // Send an encrypted text message
        await client.sendTextMessage("Hello from Node.js!");

        // Graceful disconnect
        await client.disconnect();
    } catch (error) {
        console.error("Connection failed:", error);
    }
}

main();
```

### API Reference

#### `class AdaTPClient`

**Constructor**
```typescript
new AdaTPClient(host: string, port: number)
```
Creates a new client instance.

**Methods**

- **`connect(): Promise<void>`**
  Establishes a TCP connection and performs the cryptographic handshake. Resolves when the session is secure and ready.

- **`sendTextMessage(text: string): Promise<void>`**
  Encrypts and sends a UTF-8 text message to the server. Waits for and logs an echo response (default behavior).

- **`disconnect(): Promise<void>`**
  Sends a `DISCONNECT` packet to the server and closes the socket.

## Development

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Build**
   ```bash
   npm run build
   ```

3. **Run Example**
   ```bash
   npx ts-node src/client.ts
   ```

## Protocol Support

| Feature | Status |
|---------|--------|
| Handshake (X25519) | ✅ |
| Encryption (AES-GCM) | ✅ |
| Text Messages | ✅ |
| Multi-Room Chat | ✅ |
| File Transfer | ✅ (Implemented) |
| Voice/Video | 🚧 (Planned) |

### Multi-Room Support

```typescript
// Join a specific room
await client.joinRoom('general');

// Listen for incoming messages
client.setMessageHandler((sender, text) => {
    console.log(`[${sender}]: ${text}`);
});
```

## License

MIT
# SDK-NodeJS
