import * as net from 'net';
import { generateKeyPairSync, createECDH } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4, parse as uuidParse } from 'uuid';
import {
    Packet, PacketHeader, Codec as PacketCodec,
    MessageType, PacketFlags, MAGIC_NUMBER, HEADER_SIZE
} from './protocol';
import { CryptoSession } from './crypto';

// Polyfill for X25519 if not available in older node versions (but we assume Node 16+)
// Node's crypto does not easily support raw X25519 DH with custom keys for some reason in convenient way matching Rust.
// We might need 'curve25519-js' or similar if built-in fails.
// But let's try 'crypto.diffieHellman' or 'generateKeyPair' with type 'x25519'.

const { generateKeyPairSync: genKey, diffieHellman } = require('crypto');

/**
 * AdaTP Client for Node.js
 * 
 * Manages the TCP connection, secure session state, and protocol messaging.
 * usage:
 * ```ts
 * const client = new AdaTPClient('localhost', 8443);
 * await client.connect();
 * ```
 */
export class AdaTPClient {
    private socket: net.Socket;
    private host: string;
    private port: number;
    private buffer: Buffer;
    private cryptoSession?: CryptoSession;
    private sessionId: Buffer;

    /**
     * Creates an instance of AdaTPClient.
     * @param host The server hostname or IP address.
     * @param port The server port (default typically 8443).
     */
    constructor(host: string, port: number) {
        this.host = host;
        this.port = port;
        this.socket = new net.Socket();
        this.buffer = Buffer.alloc(0);

        // Generate random session ID for client side reference, 
        // though server usually sets it on response?
        // Protocol says SessionID is in header. It should be consistent.
        // Let's generate a temporary one.
        const uuid = uuidv4();
        this.sessionId = Buffer.alloc(16);
        // Parsing UUID string to buffer is tricky without helper.
        // Using uuid.parse to write to buffer.
        // uuidParse(uuid, this.sessionId); // Requires the buffer to be passed?
        // uuidParse returns Uint8Array usually.
        const parsed = uuidParse(uuid);
        Buffer.from(parsed).copy(this.sessionId);
    }

    /**
     * Establishes connection to the server and performs the handshake.
     * @returns Promise that resolves when the secure session is established.
     * @throws Error if connection or handshake fails.
     */
    public async connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.socket.connect(this.port, this.host, async () => {
                console.log('Connected to server');
                try {
                    await this.handshake();
                    resolve();
                } catch (e) {
                    reject(e);
                }
            });

            this.socket.on('data', (data: Buffer) => {
                this.buffer = Buffer.concat([this.buffer, data]);
                this.processBuffer();
            });

            this.socket.on('error', (err: any) => {
                console.error("Socket error:", err);
            });

            this.socket.on('close', () => {
                console.log("Connection closed");
            });
        });
    }

    private async handshake() {
        // 1. Generate Ephemeral Keys (X25519)
        const kp = genKey('x25519');
        const myPriv = kp.privateKey;
        const myPub = kp.publicKey;

        // Extract raw 32 bytes from SPKI DER
        const myPubDer: Buffer = myPub.export({ format: 'der', type: 'spki' });
        // X25519 SPKI DER is 44 bytes. Last 32 is the key.
        const myRawPub = myPubDer.subarray(myPubDer.length - 32);

        // 2. Send HANDSHAKE_INIT
        const initPacket = this.createPacket(MessageType.HandshakeInit, myRawPub);
        this.sendPacket(initPacket);

        // 3. Wait for HANDSHAKE_RESPONSE
        const responsePacket = await this.readNextPacket();
        if (responsePacket.header.msgType !== MessageType.HandshakeResponse) {
            throw new Error(`Expected HandshakeResponse, got ${responsePacket.header.msgType}`);
        }

        const serverPubKey = responsePacket.payload.subarray(0, 32);

        // 4. Compute Shared Secret
        const secret = require('crypto').diffieHellman({
            publicKey: require('crypto').createPublicKey({
                key: Buffer.concat([
                    Buffer.from("302a300506032b656e032100", "hex"), // X25519 SPKI Prefix
                    serverPubKey
                ]),
                format: 'der',
                type: 'spki'
            }),
            privateKey: myPriv
        });

        // 5. Init Crypto Session
        this.cryptoSession = new CryptoSession('client', secret);

        // 6. Send HANDSHAKE_COMPLETE
        const verifyMsg = Buffer.from("Verification OK");
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(verifyMsg);

        const completePacket = this.createPacket(MessageType.HandshakeComplete, ciphertext);
        completePacket.header.flags |= PacketFlags.Encrypted;
        completePacket.header.sequence = sequence;
        completePacket.authTag = authTag;

        this.sendPacket(completePacket);
        console.log("Handshake Complete!");
    }

    // ... Helper implementations for readNextPacket, etc.

    private createPacket(type: MessageType, payload: Buffer): Packet {
        return {
            header: {
                magic: MAGIC_NUMBER,
                version: 1,
                flags: 0,
                length: payload.length,
                sequence: 0n, // Default, overridden if encrypted
                msgType: type,
                timestamp: BigInt(Date.now()),
                sessionId: this.sessionId
            },
            payload: payload
        };
    }

    private sendPacket(packet: Packet) {
        console.log(`Sending Packet: Type=${packet.header.msgType}, Len=${packet.payload.length}, Flags=${packet.header.flags}`);
        const buf = PacketCodec.encode(packet);
        // console.log("Hex:", buf.toString('hex'));
        this.socket.write(buf);
    }

    private pendingResolver: ((p: Packet) => void) | null = null;
    private messageHandler: ((sender: string, text: string) => void) | null = null;

    public setMessageHandler(handler: (sender: string, text: string) => void) {
        this.messageHandler = handler;
    }

    private processBuffer() {
        if (this.buffer.length < HEADER_SIZE) return;

        const length = this.buffer.readUInt32LE(7);
        const flags = this.buffer.readUInt16LE(5);
        const isEncrypted = (flags & PacketFlags.Encrypted) !== 0;
        const extra = isEncrypted ? 16 : 0;
        const totalLen = HEADER_SIZE + length + extra;

        if (this.buffer.length >= totalLen) {
            const raw = this.buffer.subarray(0, totalLen);
            this.buffer = this.buffer.subarray(totalLen);

            const packet = this.parsePacketBytes(raw);

            if (this.pendingResolver) {
                this.pendingResolver(packet);
                this.pendingResolver = null;
            } else {
                // Handle async messages (Chat)
                if (packet.header.msgType === MessageType.TextMessage && this.cryptoSession) {
                    if ((packet.header.flags & PacketFlags.Encrypted)) {
                        try {
                            const plaintext = this.cryptoSession.decrypt(packet);
                            // We don't have sender info in protocol yet, so sender is unknown or we parse it from text if protocol changed?
                            // Server broadcast sends: [Addr] Message
                            // Actually server sends RAW BYTES of `decrypted`.
                            // So plaintext IS the message.
                            // The protocol doesn't have sender field in Header yet.
                            // Server embeds sender in text? 
                            // In `handle_connection` server did `tx.send((addr, decrypted))`.
                            // But when sending to client: `secure_session.encrypt(&content)`.
                            // `content` is just `decrypted` bytes.
                            // Wait, server DOES NOT prepend sender in the content sent to client in my rust code?
                            // Rust: `secure_session.encrypt(&content)` where content is `decrypted`.
                            // So client receives exactly what sender sent.
                            // EXCEPT if I changed server logic?
                            // Ah, in PHP test we saw `< [ali] selam`.
                            // This format was done by PHP client: `$msg = "[$username] $line";`.
                            // So the text itself contains sender.
                            const text = plaintext.toString('utf-8');
                            if (this.messageHandler) {
                                this.messageHandler("Server", text); // Sender is embedded in text
                            } else {
                                console.log("Received:", text);
                            }
                        } catch (e) {
                            console.error("Decrypt error", e);
                        }
                    }
                } else {
                    // console.log("Received packet:", packet.header.msgType);
                }
            }

            this.processBuffer();
        }
    }

    private parsePacketBytes(raw: Buffer): Packet {
        // Manual parse similar to Rust 'from_bytes'
        // ...
        // For now return dummy

        const magic = raw.readUInt32LE(0);
        // ...

        const msgType = raw.readUInt16LE(22); // Offset
        // Wait, offsets in RFC:
        // Magic(0): 4
        // Version(4): 1
        // Flags(5): 2
        // Length(7): 4
        // Sequence(11): 8
        // MsgType(19): 2
        // Timestamp(21): 8
        // Session(29): 16
        // Header Size: 45

        // Correct offset for MsgType is 19.
        const type = raw.readUInt16LE(19);
        const length = raw.readUInt32LE(7);
        const flags = raw.readUInt16LE(5);

        const payload = raw.subarray(HEADER_SIZE, HEADER_SIZE + length);

        let authTag: Buffer | undefined = undefined;
        if ((flags & PacketFlags.Encrypted) !== 0) {
            // AuthTag is AFTER payload
            const tagStart = HEADER_SIZE + length;
            authTag = raw.subarray(tagStart, tagStart + 16);
        }

        const packet: Packet = {
            header: {
                magic,
                version: raw.readUInt8(4),
                flags: flags,
                length: length,
                sequence: raw.readBigUInt64LE(11),
                msgType: type,
                timestamp: raw.readBigUInt64LE(21),
                sessionId: raw.subarray(29, 45)
            },
            payload,
            authTag
        };

        return packet;
    }

    public readNextPacket(): Promise<Packet> {
        return new Promise(resolve => {
            this.pendingResolver = resolve;
        });
    }
    /**
     * Sends an encrypted text message to the server.
     * @param text The message string to send.
     */
    public async sendTextMessage(text: string): Promise<void> {
        if (!this.cryptoSession) throw new Error("No session");

        const payload = Buffer.from(text, 'utf-8');
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(payload);

        const packet = this.createPacket(MessageType.TextMessage, ciphertext);
        packet.header.flags |= PacketFlags.Encrypted;
        packet.header.sequence = sequence;
        packet.authTag = authTag;

        this.sendPacket(packet);
        // Echo will be handled by message handler
    }

    public async joinRoom(room: string): Promise<void> {
        if (!this.cryptoSession) throw new Error("No secure session");

        const payload = Buffer.from(room, 'utf-8');
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(payload);

        const packet = this.createPacket(MessageType.JoinRoom, ciphertext);
        packet.header.flags |= PacketFlags.Encrypted;
        packet.header.sequence = sequence;
        packet.authTag = authTag;

        this.sendPacket(packet);
        console.log(`Joined room: ${room}`);
    }

    public async authenticate(username: string, password: string): Promise<void> {
        if (!this.cryptoSession) throw new Error("No session");

        const payload = Buffer.from(JSON.stringify({ username, password }), 'utf-8');
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(payload);

        const packet = this.createPacket(MessageType.AuthRequest, ciphertext);
        packet.header.flags |= PacketFlags.Encrypted;
        packet.header.sequence = sequence;
        packet.authTag = authTag;

        this.sendPacket(packet);

        // Wait for Auth Success/Failure
        const response = await this.readNextPacket();

        // Decrypt response
        if (response.header.flags & PacketFlags.Encrypted) {
            const plaintext = this.cryptoSession.decrypt(response);
            if (response.header.msgType === MessageType.AuthSuccess) {
                const user = JSON.parse(plaintext.toString());
                console.log("Auth Successful:", user);
                return;
            } else if (response.header.msgType === MessageType.AuthFailure) {
                const err = plaintext.toString();
                throw new Error(`Authentication Failed: ${err}`);
            }
        }

        throw new Error("Unexpected packet during auth");
    }

    public async sendFile(filePath: string): Promise<void> {
        if (!this.cryptoSession) throw new Error("Not connected secure");

        const buffer = fs.readFileSync(filePath);
        const filename = path.basename(filePath);
        const size = buffer.length;
        const fileId = uuidv4();

        // Init
        const initData = { id: fileId, filename: filename, size: size };
        const initJson = JSON.stringify(initData);
        await this.sendEncryptedRaw(MessageType.FileInit, Buffer.from(initJson));

        // Chunks
        const CHUNK_SIZE = 16384;
        let offset = 0;
        const fileIdBytes = uuidParse(fileId);
        const fileIdBuf = Buffer.from(fileIdBytes as Uint8Array);

        console.log(`Sending file ${filename} (${size} bytes) ID: ${fileId}`);

        while (offset < size) {
            const end = Math.min(offset + CHUNK_SIZE, size);
            const chunkData = buffer.slice(offset, end);
            const chunkPayload = Buffer.concat([fileIdBuf, chunkData]);

            await this.sendEncryptedRaw(MessageType.FileChunk, chunkPayload);
            offset += CHUNK_SIZE;
            // throttle slightly
            await new Promise(r => setTimeout(r, 2));
        }

        // Complete
        await this.sendEncryptedRaw(MessageType.FileComplete, fileIdBuf);
        console.log("File sent.");
    }

    private async sendEncryptedRaw(type: MessageType, payload: Buffer): Promise<void> {
        if (!this.cryptoSession) return;
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(payload);
        const packet = this.createPacket(type, ciphertext);
        packet.header.flags |= PacketFlags.Encrypted;
        packet.header.sequence = sequence;
        packet.authTag = authTag;
        this.sendPacket(packet);
    }

    /**
     * Reads the next incoming text message.
     */
    public async readNextTextMessage(): Promise<string> {
        while (true) {
            const packet = await this.readNextPacket();
            if (packet.header.msgType === MessageType.TextMessage && this.cryptoSession) {
                // Decrypt
                if ((packet.header.flags & PacketFlags.Encrypted)) {
                    // Using the existing pattern from line 279
                    // Assuming 'Packet' object has all info including payload, tag, seq
                    // But wait, the `packet` variable here IS a Packet object.
                    const plaintext = this.cryptoSession.decrypt(packet);
                    return plaintext.toString('utf-8');
                }
            }
            // Ignore other packets or handle ping/pong?
        }
    }

    /**
     * Closes the connection gracefully by sending a DISCONNECT packet.
     */
    public async disconnect(): Promise<void> {
        const packet = this.createPacket(MessageType.Disconnect, Buffer.alloc(0));
        this.sendPacket(packet);
        console.log("Sent DISCONNECT");
        this.socket.end();
    }
}

async function main() {
    const client = new AdaTPClient('127.0.0.1', 8443);
    try {
        await client.connect();
        await client.sendTextMessage("Hello from Node.js!");
        await client.disconnect();
    } catch (e) {
        console.error("Error:", e);
    }
}

if (require.main === module) {
    main();
}
