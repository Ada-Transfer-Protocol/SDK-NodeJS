import WebSocket from 'ws';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4, parse as uuidParse } from 'uuid';
import {
    Packet, Codec as PacketCodec,
    MessageType, PacketFlags, MAGIC_NUMBER, HEADER_SIZE
} from './protocol';
import { CryptoSession } from './crypto';

export const ADATP_LOCALES = ['en', 'tr', 'it', 'fr', 'de', 'zh', 'ja', 'hi', 'ar'] as const;

export interface AdaTPClientOptions {
    /** WebSocket path on the server. Default: "/ws". */
    path?: string;
    /** Use wss:// instead of ws:// when constructing from host+port. */
    secure?: boolean;
    /** SDK language for user-facing SDK strings. Default 'en'.
     *  The wire protocol is language-neutral; this is client-side metadata. */
    locale?: string;
}

/**
 * AdaTP client for Node.js.
 *
 * Transport is WebSocket (binary frames, one AdaTP packet per message).
 * The connection is upgraded to an encrypted session via an X25519 handshake
 * (HKDF-SHA256 key derivation, AES-256-GCM packet encryption).
 *
 * ```ts
 * const client = new AdaTPClient('127.0.0.1', 3000);
 * await client.connect();                      // WS + secure handshake
 * await client.authenticate('user1', 'password123');
 * await client.joinRoom('lobby');
 * await client.sendTextMessage('Hello!');
 * ```
 *
 * A full URL is also accepted: `new AdaTPClient('ws://example.com:3000/ws')`.
 */
export class AdaTPClient {
    private url: string;
    private ws: WebSocket | null = null;
    private cryptoSession?: CryptoSession;
    private sessionId: Buffer;

    private pendingResolvers: Array<(p: Packet) => void> = [];
    private inbox: Packet[] = [];
    private messageHandler: ((sender: string, text: string) => void) | null = null;
    private gameStateHandler: ((sender: string, state: any) => void) | null = null;
    private toolPending = new Map<string, (p: Packet) => void>();
    private closed = false;
    /** Active SDK locale (normalized; falls back to 'en'). */
    public locale: string = 'en';

    constructor(hostOrUrl: string, port?: number, options: AdaTPClientOptions = {}) {
        if (hostOrUrl.startsWith('ws://') || hostOrUrl.startsWith('wss://')) {
            this.url = hostOrUrl;
        } else {
            const scheme = options.secure ? 'wss' : 'ws';
            const p = port ?? 3000;
            const wsPath = options.path ?? '/ws';
            this.url = `${scheme}://${hostOrUrl}:${p}${wsPath}`;
        }

        this.locale = (ADATP_LOCALES as readonly string[]).includes(options.locale || '')
            ? (options.locale as string) : 'en';

        this.sessionId = Buffer.alloc(16);
        Buffer.from(uuidParse(uuidv4())).copy(this.sessionId);
    }

    /** Switches the SDK language at runtime (one of ADATP_LOCALES). */
    public setLocale(locale: string): void {
        this.locale = (ADATP_LOCALES as readonly string[]).includes(locale) ? locale : 'en';
    }

    /** Client identity as sent in every packet header (hex). */
    public getSessionId(): string {
        return this.sessionId.toString('hex');
    }

    /**
     * Opens the WebSocket and performs the X25519 secure handshake.
     */
    public async connect(): Promise<void> {
        await new Promise<void>((resolve, reject) => {
            const ws = new WebSocket(this.url);
            this.ws = ws;

            ws.on('open', () => resolve());
            ws.on('message', (data: WebSocket.RawData) => {
                const buf = Array.isArray(data)
                    ? Buffer.concat(data)
                    : Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
                this.handleIncoming(buf);
            });
            ws.on('error', (err) => reject(err));
            ws.on('close', () => { this.closed = true; });
        });

        await this.handshake();
    }

    private async handshake(): Promise<void> {
        const { generateKeyPairSync, diffieHellman, createPublicKey } = require('crypto');

        // 1. Ephemeral X25519 key pair; raw public key = last 32 bytes of SPKI DER.
        const kp = generateKeyPairSync('x25519');
        const myPubDer: Buffer = kp.publicKey.export({ format: 'der', type: 'spki' });
        const myRawPub = myPubDer.subarray(myPubDer.length - 32);

        // 2. HANDSHAKE_INIT carries our public key.
        this.sendPacket(this.createPacket(MessageType.HandshakeInit, Buffer.from(myRawPub)));

        // 3. HANDSHAKE_RESPONSE carries the server's public key.
        const response = await this.readNextPacketOfType([MessageType.HandshakeResponse]);
        if (response.payload.length < 32) {
            throw new Error('Server did not provide a key (plaintext-only server?)');
        }
        const serverPub = response.payload.subarray(0, 32);

        // 4. Shared secret + session keys.
        const secret = diffieHellman({
            publicKey: createPublicKey({
                key: Buffer.concat([
                    Buffer.from('302a300506032b656e032100', 'hex'), // X25519 SPKI prefix
                    serverPub
                ]),
                format: 'der',
                type: 'spki'
            }),
            privateKey: kp.privateKey
        });
        this.cryptoSession = new CryptoSession('client', secret);

        // 5. HANDSHAKE_COMPLETE proves we derived the same keys.
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(Buffer.from('Verification OK'));
        const complete = this.createPacket(MessageType.HandshakeComplete, ciphertext);
        complete.header.flags |= PacketFlags.Encrypted;
        complete.header.sequence = sequence;
        complete.authTag = authTag;
        this.sendPacket(complete);
    }

    /**
     * Sends credentials; resolves with the server-assigned identity or throws
     * on AuthFailure.
     */
    public async authenticate(username: string, password: string): Promise<{ user_id: string, username: string, role: string }> {
        const body = Buffer.from(JSON.stringify({ username, password }), 'utf-8');
        this.sendSecure(MessageType.AuthRequest, body);

        const response = await this.readNextPacketOfType([MessageType.AuthSuccess, MessageType.AuthFailure]);
        const plaintext = this.decryptIfNeeded(response);

        if (response.header.msgType === MessageType.AuthSuccess) {
            return JSON.parse(plaintext.toString('utf-8'));
        }
        throw new Error(`Authentication failed: ${plaintext.toString('utf-8')}`);
    }

    /** Joins a room; resolves once the server confirms with RoomJoined. */
    public async joinRoom(room: string): Promise<string> {
        this.sendSecure(MessageType.JoinRoom, Buffer.from(room, 'utf-8'));
        const response = await this.readNextPacketOfType([MessageType.RoomJoined, MessageType.AuthFailure]);
        const plaintext = this.decryptIfNeeded(response);
        if (response.header.msgType === MessageType.RoomJoined) {
            return plaintext.toString('utf-8');
        }
        throw new Error(`Join failed: ${plaintext.toString('utf-8')}`);
    }

    /** Sends an encrypted text message to the current room. */
    public async sendTextMessage(text: string): Promise<void> {
        this.sendSecure(MessageType.TextMessage, Buffer.from(text, 'utf-8'));
    }

    /** Streams a file to the current room (FileInit → FileChunk* → FileComplete). */
    public async sendFile(filePath: string): Promise<void> {
        const buffer = fs.readFileSync(filePath);
        const fileId = uuidv4();
        const fileIdBuf = Buffer.from(uuidParse(fileId) as Uint8Array);

        const initJson = JSON.stringify({ id: fileId, filename: path.basename(filePath), size: buffer.length });
        this.sendSecure(MessageType.FileInit, Buffer.from(initJson));

        const CHUNK_SIZE = 16384;
        for (let offset = 0; offset < buffer.length; offset += CHUNK_SIZE) {
            const chunk = buffer.subarray(offset, Math.min(offset + CHUNK_SIZE, buffer.length));
            this.sendSecure(MessageType.FileChunk, Buffer.concat([fileIdBuf, chunk]));
            await new Promise(r => setTimeout(r, 2)); // gentle pacing
        }

        this.sendSecure(MessageType.FileComplete, fileIdBuf);
    }

    /** Handler for asynchronous text messages (chat traffic). */
    public setMessageHandler(handler: (sender: string, text: string) => void) {
        this.messageHandler = handler;
    }

    // ------------------------------------------------------------------
    // GameState (0x0050) — room-routed opaque state, JSON recommended
    // ------------------------------------------------------------------

    /** Broadcasts a game state to the current room. Objects are JSON-encoded. */
    public async sendGameState(state: object | Buffer): Promise<void> {
        const payload = Buffer.isBuffer(state)
            ? state
            : Buffer.from(JSON.stringify(state), 'utf-8');
        this.sendSecure(MessageType.GameState, payload);
    }

    /** Handler for incoming game states (parsed as JSON when possible). */
    public setGameStateHandler(handler: (sender: string, state: any) => void) {
        this.gameStateHandler = handler;
    }

    /** Resolves with the next GameState payload (JSON-parsed when possible). */
    public async readNextGameState(): Promise<any> {
        const packet = await this.readNextPacketOfType([MessageType.GameState]);
        return this.parseGamePayload(packet);
    }

    private parseGamePayload(packet: Packet): any {
        const raw = this.decryptIfNeeded(packet);
        try { return JSON.parse(raw.toString('utf-8')); } catch { return raw; }
    }

    // ------------------------------------------------------------------
    // Tools (0x0070-0x0072) — plugin tool platform
    // ------------------------------------------------------------------

    /**
     * Calls a server-side tool and resolves with its result.
     * Rejects with the tool error (code + message) on ToolError.
     */
    public async callTool(tool: string, args: object = {}, timeoutMs = 15000): Promise<any> {
        const id = uuidv4();
        const body = Buffer.from(JSON.stringify({ id, tool, args }), 'utf-8');

        const resultPromise = new Promise<Packet>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.toolPending.delete(id);
                reject(new Error(`Tool call '${tool}' timed out after ${timeoutMs}ms`));
            }, timeoutMs);
            this.toolPending.set(id, (p) => { clearTimeout(timer); resolve(p); });
        });

        this.sendSecure(MessageType.ToolCall, body);
        const packet = await resultPromise;
        const parsed = JSON.parse(this.decryptIfNeeded(packet).toString('utf-8'));

        if (packet.header.msgType === MessageType.ToolResult && parsed.ok) {
            return parsed.result;
        }
        const err = parsed.error ?? { code: 'tool_failed', message: 'unknown error' };
        const e: any = new Error(`Tool '${tool}' failed: ${err.code}: ${err.message}`);
        e.code = err.code;
        throw e;
    }

    /** Lists the tools available on the server (built-in system.list_tools). */
    public async listTools(): Promise<Array<{ name: string, description: string, schema: object, plugin: string }>> {
        const result = await this.callTool('system.list_tools', {});
        return result.tools ?? [];
    }

    /** Resolves with the next decrypted TextMessage (skips other packets). */
    public async readNextTextMessage(): Promise<string> {
        while (true) {
            const packet = await this.readNextPacket();
            if (packet.header.msgType === MessageType.TextMessage) {
                return this.decryptIfNeeded(packet).toString('utf-8');
            }
        }
    }

    /** Resolves with the next packet (inbox first, then live traffic). */
    public readNextPacket(): Promise<Packet> {
        const queued = this.inbox.shift();
        if (queued) return Promise.resolve(queued);
        return new Promise(resolve => {
            this.pendingResolvers.push(resolve);
        });
    }

    /**
     * Resolves with the next packet whose type is in `types`; unrelated
     * packets (e.g. presence updates or chat traffic arriving mid-request)
     * are queued for later consumption instead of being lost.
     */
    public async readNextPacketOfType(types: number[], timeoutMs = 10000): Promise<Packet> {
        const idx = this.inbox.findIndex(p => types.includes(p.header.msgType));
        if (idx >= 0) return this.inbox.splice(idx, 1)[0];

        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            const packet = await new Promise<Packet | null>(resolve => {
                const entry = (p: Packet) => { clearTimeout(timer); resolve(p); };
                const timer = setTimeout(() => {
                    const i = this.pendingResolvers.indexOf(entry);
                    if (i >= 0) this.pendingResolvers.splice(i, 1);
                    resolve(null);
                }, Math.max(1, deadline - Date.now()));
                this.pendingResolvers.push(entry);
            });
            if (!packet) break;
            if (types.includes(packet.header.msgType)) return packet;
            this.inbox.push(packet);
        }
        throw new Error(`Timeout waiting for packet of type [${types.map(t => '0x' + t.toString(16)).join(', ')}]`);
    }

    /** Sends Disconnect and closes the socket. */
    public async disconnect(): Promise<void> {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.sendPacket(this.createPacket(MessageType.Disconnect, Buffer.alloc(0)));
            this.ws.close();
        }
        this.closed = true;
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private handleIncoming(raw: Buffer) {
        if (raw.length < HEADER_SIZE || raw.readUInt32LE(0) !== MAGIC_NUMBER) return;
        const packet = this.parsePacketBytes(raw);

        // Tool results are correlated by id and never enter the general queue.
        if (packet.header.msgType === MessageType.ToolResult ||
            packet.header.msgType === MessageType.ToolError) {
            try {
                const body = JSON.parse(this.decryptIfNeeded(packet).toString('utf-8'));
                const waiter = this.toolPending.get(body.id);
                if (waiter) {
                    this.toolPending.delete(body.id);
                    waiter(packet);
                    return;
                }
            } catch { /* fall through to the generic path */ }
        }

        const resolver = this.pendingResolvers.shift();
        if (resolver) {
            resolver(packet);
            return;
        }

        if (packet.header.msgType === MessageType.TextMessage && this.messageHandler) {
            try {
                const text = this.decryptIfNeeded(packet).toString('utf-8');
                const sender = packet.header.sessionId.toString('hex');
                this.messageHandler(sender, text);
            } catch {
                // Undecryptable traffic is dropped.
            }
            return;
        }

        if (packet.header.msgType === MessageType.GameState && this.gameStateHandler) {
            try {
                const sender = packet.header.sessionId.toString('hex');
                this.gameStateHandler(sender, this.parseGamePayload(packet));
            } catch { /* dropped */ }
            return;
        }

        this.inbox.push(packet);
        if (this.inbox.length > 1024) this.inbox.shift();
    }

    private decryptIfNeeded(packet: Packet): Buffer {
        if ((packet.header.flags & PacketFlags.Encrypted) !== 0) {
            if (!this.cryptoSession) throw new Error('Encrypted packet without a session');
            return this.cryptoSession.decrypt(packet);
        }
        return packet.payload;
    }

    private sendSecure(type: MessageType, payload: Buffer) {
        if (!this.cryptoSession) throw new Error('Secure session not established (call connect() first)');
        const { ciphertext, authTag, sequence } = this.cryptoSession.encrypt(payload);
        const packet = this.createPacket(type, ciphertext);
        packet.header.flags |= PacketFlags.Encrypted;
        packet.header.sequence = sequence;
        packet.authTag = authTag;
        this.sendPacket(packet);
    }

    private createPacket(type: MessageType, payload: Buffer): Packet {
        return {
            header: {
                magic: MAGIC_NUMBER,
                version: 1,
                flags: 0,
                length: payload.length,
                sequence: 0n,
                msgType: type,
                timestamp: BigInt(Date.now()),
                sessionId: this.sessionId
            },
            payload
        };
    }

    private sendPacket(packet: Packet) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error('WebSocket is not open');
        }
        this.ws.send(PacketCodec.encode(packet));
    }

    private parsePacketBytes(raw: Buffer): Packet {
        const flags = raw.readUInt16LE(5);
        const length = raw.readUInt32LE(7);
        const payload = raw.subarray(HEADER_SIZE, HEADER_SIZE + length);

        let authTag: Buffer | undefined;
        if ((flags & PacketFlags.Encrypted) !== 0) {
            const tagStart = HEADER_SIZE + length;
            authTag = raw.subarray(tagStart, tagStart + 16);
        }

        return {
            header: {
                magic: raw.readUInt32LE(0),
                version: raw.readUInt8(4),
                flags,
                length,
                sequence: raw.readBigUInt64LE(11),
                msgType: raw.readUInt16LE(19),
                timestamp: raw.readBigUInt64LE(21),
                sessionId: Buffer.from(raw.subarray(29, 45))
            },
            payload,
            authTag
        };
    }
}
