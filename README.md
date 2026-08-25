# AdaTP Node.js SDK

A high-performance, strongly-typed Node.js/TypeScript client library for the **Ada Transfer Protocol (AdaTP)**. This SDK implementation fully supports X25519/AES-256-GCM encryption, room management, and efficient chunked file transfers.

## 📦 Features
*   **Secure:** Built-in End-to-End Encryption (Handshake + Session).
*   **Typed:** Written in TypeScript with full type definitions.
*   **Async/Await:** Modern, promise-based API for connection and logic.
*   **Files:** Built-in helpers for streaming file uploads and downloads.

## 🚀 Installation

```bash
npm install
npm run build
```

## 🛠️ Usage

### 1. Basic Chat Client

```typescript
import { AdaTPClient } from './src/client';

async function main() {
    // 1. Initialize
    const client = new AdaTPClient('127.0.0.1', 3000);

    try {
        // 2. Connect & Handshake
        await client.connect();

        // 3. Authenticate
        await client.authenticate("username", "password");

        // 4. Handle Incoming Messages
        client.setMessageHandler((sender, text) => {
             console.log(`[${sender}] ${text}`);
        });
        
        // 5. Join Room
        await client.joinRoom("general");

        // 6. Send Message
        await client.sendTextMessage("Hello World!");

    } catch (err) {
        console.error("Error:", err);
    }
}
main();
```

### 2. File Transfer

The SDK provides low-level control for handling file packets (`FileInit`, `FileChunk`, `FileComplete`).

**Sending a File:**
```typescript
await client.sendFile("/path/to/large_file.zip");
```

**Receiving a File:**
Receiving involves listening for packet types. See `filetransfer_example.ts` for a complete implementation of a robust download manager.

## 📂 Examples

*   **Chat CLI:** `npx ts-node example.ts`
    *   Interactive command-line chat application.
*   **File Transfer:** `npx ts-node filetransfer_example.ts`
    *   Demonstrates sending a generated text file and receiving broadcasts back to the `downloads/` folder.

## 🔧 Configuration

The client connects to `ws://127.0.0.1:3000/ws` (WebSocket) by default. A full URL is also accepted: `new AdaTPClient("wss://example.com/ws")`. Ensure your AdaTP server is running and accessible.

## Language / locale

The client takes a `locale` option for its user-facing strings (client-side
metadata — the wire protocol is language-neutral). Default `en`; supported:
`en tr it fr de zh ja hi ar`.

```ts
const client = new AdaTPClient('127.0.0.1', 3000, { locale: 'tr' });
client.setLocale('de'); // switch at runtime
```
