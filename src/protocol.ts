export enum MessageType {
    HandshakeInit = 0x0001,
    HandshakeResponse = 0x0002,
    HandshakeComplete = 0x0003,
    AuthRequest = 0x0010,
    AuthChallenge = 0x0011,
    AuthResponse = 0x0012,
    AuthSuccess = 0x0013,
    AuthFailure = 0x0014,
    TextMessage = 0x0020,
    TextAck = 0x0021,
    TextRead = 0x0022,
    FileInit = 0x0030,
    FileChunk = 0x0031,
    FileAck = 0x0032,
    FileComplete = 0x0033,
    FileCancel = 0x0034,
    VoiceInit = 0x0040,
    VoiceOffer = 0x0041,
    VoiceAnswer = 0x0042,
    VoiceIce = 0x0043,
    VoiceData = 0x0044,
    VoiceEnd = 0x0045,
    GameState = 0x0050,
    PresenceUpdate = 0x0060,
    TypingIndicator = 0x0061,
    ToolCall = 0x0070,
    ToolResult = 0x0071,
    ToolError = 0x0072,
    Ping = 0x0080,
    Pong = 0x0081,
    VideoInit = 0x0090,
    VideoOffer = 0x0091,
    VideoAnswer = 0x0092,
    VideoData = 0x0093,
    VideoEnd = 0x0094,
    JoinRoom = 0x00A0,
    RoomJoined = 0x00A1,
    ClientEvent = 0x00A2,
    Disconnect = 0x00FF
}

export enum PacketFlags {
    None = 0,
    Encrypted = 0x0001,
    Compressed = 0x0002,
    Reliable = 0x0004
}

export const MAGIC_NUMBER = 0x41444154;
export const HEADER_SIZE = 45;

export interface PacketHeader {
    magic: number;
    version: number;
    flags: number;
    length: number;
    sequence: bigint;
    msgType: number;
    timestamp: bigint;
    sessionId: Buffer; // 16 bytes
}

export interface Packet {
    header: PacketHeader;
    payload: Buffer;
    authTag?: Buffer; // 16 bytes
}

export class Codec {
    /**
     * The 45-byte header, serialized exactly as on the wire. Also used, in
     * protocol v2, as the AEAD additional authenticated data — so it must be
     * byte-identical to the server's `PacketHeader::header_bytes()`.
     */
    static encodeHeader(header: PacketHeader): Buffer {
        const buf = Buffer.alloc(HEADER_SIZE);
        let offset = 0;
        buf.writeUInt32LE(header.magic, offset); offset += 4;       // Magic (4) LE
        buf.writeUInt8(header.version, offset); offset += 1;        // Version (1)
        buf.writeUInt16LE(header.flags, offset); offset += 2;       // Flags (2)
        buf.writeUInt32LE(header.length, offset); offset += 4;      // Length (4)
        buf.writeBigUInt64LE(header.sequence, offset); offset += 8; // Sequence (8)
        buf.writeUInt16LE(header.msgType, offset); offset += 2;     // MsgType (2)
        buf.writeBigUInt64LE(header.timestamp, offset); offset += 8;// Timestamp (8)
        header.sessionId.copy(buf, offset);                        // SessionID (16)
        return buf;
    }

    static encode(packet: Packet): Buffer {
        const header = Codec.encodeHeader(packet.header);
        const parts: Buffer[] = [header, packet.payload];
        if (packet.authTag) parts.push(packet.authTag);
        return Buffer.concat(parts);
    }
}
