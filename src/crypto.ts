import { diffieHellman } from 'crypto';

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Packet, PacketFlags } from './protocol';

export class CryptoSession {
    private clientWriteKey: Buffer;
    private serverWriteKey: Buffer;
    private clientIvRoot: Buffer;
    private serverIvRoot: Buffer;

    private mySequence: bigint = 1n;
    private peerSequence: bigint = 1n;

    private role: 'client' | 'server';

    constructor(role: 'client' | 'server', sharedSecret: Buffer) {
        this.role = role;
        // Derive keys
        // Using sync HKDF for simplicity implementation, assuming 'hkdf' package supports it or wrapper.
        // Actually 'hkdf' is usually async or callback based in some libs.
        // Let's assume we use node's built-in hkdf if available (Node 15+) or just mock for now if not easy.
        // Node's crypto has 'hkdfSync' since v15.0.0.

        // Let's adhere to "Reference Implementation" logic.
        // Salt = 32 bytes of zeros.
        const salt = Buffer.alloc(32);

        const { hkdfSync } = require('crypto');

        // Derive master secret? No, we use shared secret as IKM directly as per Rust impl.

        // Client Write Key (32)
        this.clientWriteKey = Buffer.from(hkdfSync('sha256', sharedSecret, salt, 'client_write', 32));

        // Server Write Key (32)
        this.serverWriteKey = Buffer.from(hkdfSync('sha256', sharedSecret, salt, 'server_write', 32));

        // Client IV Root (12)
        this.clientIvRoot = Buffer.from(hkdfSync('sha256', sharedSecret, salt, 'client_iv', 12));

        // Server IV Root (12)
        this.serverIvRoot = Buffer.from(hkdfSync('sha256', sharedSecret, salt, 'server_iv', 12));
    }

    public encrypt(plaintext: Buffer): { ciphertext: Buffer, authTag: Buffer, sequence: bigint } {
        const seq = this.mySequence;
        const iv = this.computeIv(seq, this.role);

        const key = this.role === 'client' ? this.clientWriteKey : this.serverWriteKey;

        const cipher = createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const authTag = cipher.getAuthTag();

        this.mySequence++;
        return { ciphertext, authTag, sequence: seq };
    }

    public decrypt(packet: Packet): Buffer {
        // if (!packet.header.flags & PacketFlags.Encrypted) return packet.payload;
        // Simplified check

        const seq = packet.header.sequence;
        // Replay check logic here (TODO)

        const peerRole = this.role === 'client' ? 'server' : 'client';
        const iv = this.computeIv(seq, peerRole);
        const key = peerRole === 'client' ? this.clientWriteKey : this.serverWriteKey;

        if (!packet.authTag) throw new Error("Missing auth tag");

        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(packet.authTag);

        const plaintext = Buffer.concat([decipher.update(packet.payload), decipher.final()]);

        if (seq >= this.peerSequence) {
            this.peerSequence = seq + 1n;
        }

        return plaintext;
    }

    private computeIv(sequence: bigint, role: 'client' | 'server'): Buffer {
        const root = role === 'client' ? this.clientIvRoot : this.serverIvRoot;
        const iv = Buffer.alloc(12);
        root.copy(iv);

        // XOR last 8 bytes with sequence
        // Sequence is Little Endian 64-bit int.

        const seqBuf = Buffer.alloc(8);
        seqBuf.writeBigUInt64LE(sequence);

        for (let i = 0; i < 8; i++) {
            iv[4 + i] ^= seqBuf[i];
        }

        return iv;
    }
}
