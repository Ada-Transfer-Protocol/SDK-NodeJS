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
    static encode(packet: Packet): Buffer {
        const payloadLen = packet.payload.length;
        const authTagLen = packet.authTag ? 16 : 0;
        const totalLen = HEADER_SIZE + payloadLen + authTagLen;

        const buf = Buffer.alloc(totalLen);
        let offset = 0;

        // Magic (4) - Little Endian !
        buf.writeUInt32LE(packet.header.magic, offset); offset += 4;

        // Version (1)
        buf.writeUInt8(packet.header.version, offset); offset += 1;

        // Flags (2)
        buf.writeUInt16LE(packet.header.flags, offset); offset += 2;

        // Length (4)
        buf.writeUInt32LE(packet.header.length, offset); offset += 4;

        // Sequence (8)
        buf.writeBigUInt64LE(packet.header.sequence, offset); offset += 8;

        // MsgType (2)
        buf.writeUInt16LE(packet.header.msgType, offset); offset += 2;

        // Timestamp (8)
        buf.writeBigUInt64LE(packet.header.timestamp, offset); offset += 8;

        // SessionID (16)
        packet.header.sessionId.copy(buf, offset); offset += 16;

        // Payload
        packet.payload.copy(buf, offset); offset += packet.payload.length;

        // AuthTag
        if (packet.authTag) {
            packet.authTag.copy(buf, offset);
        }

        return buf;
    }

    // Incomplete, just structure definition for now.
    // Full parsing logic will be in Connection class or similar.
}
