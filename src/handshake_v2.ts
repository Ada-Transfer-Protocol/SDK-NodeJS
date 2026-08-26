/**
 * AdaTP protocol **v2** — client side of the authenticated (SIGMA-style)
 * handshake.
 *
 * This mirrors, byte-for-byte, the server reference implementation
 * (`core/src/session/handshake_v2.rs`) and the construction the ProVerif model
 * proved secure (`docs/spec/12-authenticated-handshake.md`,
 * `docs/spec/formal/`). The security-relevant step is entirely here:
 *
 *   1. the server key it offers MUST equal the pinned key `spk_S`; and
 *   2. the Ed25519 signature MUST verify over
 *        th = SHA-256( "AdaTP-v2-handshake" || 0x02 || epk_C || epk_S || spk_S )
 *
 * A client MUST perform both checks BEFORE deriving any key material. Without
 * the pin, a valid-but-attacker-signed hello would pass (2); without (2), a
 * substituted ephemeral would let an on-path attacker MITM the DH. Together
 * they close v1's man-in-the-middle.
 *
 * The X25519 -> HKDF-SHA256 session that follows is unchanged from v1.
 */
import { createHash, createPublicKey, verify as nodeVerify, timingSafeEqual } from 'crypto';

/** Protocol version byte carried in the frame header for a v2 handshake. */
export const PROTOCOL_V2 = 2;
/** Domain-separation label for the signed transcript. */
export const LABEL_HS = Buffer.from('AdaTP-v2-handshake', 'utf-8');
/** Domain-separation label for the client's key-confirmation ("Finished"). */
export const FINISHED_LABEL = Buffer.from('AdaTP-v2-finished', 'utf-8');
/** Wire length of the server response: epk_S(32) || spk_S(32) || sig(64). */
export const SERVER_HELLO_LEN = 128;

/** SPKI DER prefix for an Ed25519 public key (OID 1.3.101.112). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** A handshake failure carrying a stable, machine-readable `code`. */
export class AdaTPHandshakeError extends Error {
    public readonly code: string;
    constructor(code: string, message: string) {
        super(message);
        this.name = 'AdaTPHandshakeError';
        this.code = code;
    }
}

/**
 * th = SHA-256( LABEL_HS || 0x02 || epk_C || epk_S || spk_S ). Pure function of
 * the three 32-byte public keys — identical to the server's `transcript_hash`.
 */
export function transcriptHash(epkC: Buffer, epkS: Buffer, spkS: Buffer): Buffer {
    const h = createHash('sha256');
    h.update(LABEL_HS);
    h.update(Buffer.from([PROTOCOL_V2]));
    h.update(epkC);
    h.update(epkS);
    h.update(spkS);
    return h.digest();
}

/** Verify an Ed25519 signature given the raw 32-byte public key. */
export function verifyEd25519(publicKeyRaw: Buffer, message: Buffer, signature: Buffer): boolean {
    if (publicKeyRaw.length !== 32 || signature.length !== 64) return false;
    try {
        const key = createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyRaw]),
            format: 'der',
            type: 'spki',
        });
        // Ed25519 is a "pure" signature scheme: the algorithm argument is null.
        return nodeVerify(null, message, key, signature);
    } catch {
        return false;
    }
}

export interface ClientVerified {
    /** The server's ephemeral X25519 public key; DH against this. */
    epkS: Buffer;
    /** The transcript hash, for the Finished confirmation. */
    transcriptHash: Buffer;
}

/**
 * Verify a v2 `HandshakeResponse` against the pinned server identity. Returns
 * the server ephemeral + transcript hash on success; throws
 * {@link AdaTPHandshakeError} (`malformed_server_hello` | `unknown_identity` |
 * `signature_verification_failed`) otherwise. No key material is derived here —
 * the caller derives only after this returns.
 */
export function verifyServerHello(pinnedSpkS: Buffer, epkC: Buffer, response: Buffer): ClientVerified {
    if (response.length !== SERVER_HELLO_LEN) {
        throw new AdaTPHandshakeError(
            'malformed_server_hello',
            `expected ${SERVER_HELLO_LEN} bytes, got ${response.length}`,
        );
    }
    const epkS = response.subarray(0, 32);
    const spkS = response.subarray(32, 64);
    const sig = response.subarray(64, 128);

    // (1) Identity: constant-time compare against the pinned key.
    if (pinnedSpkS.length !== 32 || !timingSafeEqual(spkS, pinnedSpkS)) {
        throw new AdaTPHandshakeError('unknown_identity', 'server key does not match the pinned key');
    }
    // (2) Authenticity: re-derive th ourselves and check the signature.
    const th = transcriptHash(epkC, epkS, spkS);
    if (!verifyEd25519(spkS, th, sig)) {
        throw new AdaTPHandshakeError('signature_verification_failed', 'server signature did not verify');
    }
    return { epkS: Buffer.from(epkS), transcriptHash: th };
}

/** The client's key-confirmation plaintext: FINISHED_LABEL || th. */
export function finishedPlaintext(th: Buffer): Buffer {
    return Buffer.concat([FINISHED_LABEL, th]);
}

/** Normalize a pinned key given as hex string or raw 32-byte Buffer. */
export function normalizePinnedKey(key: string | Buffer): Buffer {
    const buf = Buffer.isBuffer(key) ? key : Buffer.from(key.trim(), 'hex');
    if (buf.length !== 32) {
        throw new AdaTPHandshakeError(
            'invalid_pinned_key',
            `pinned server key must be 32 bytes (got ${buf.length}); pass hex or a Buffer`,
        );
    }
    return buf;
}
