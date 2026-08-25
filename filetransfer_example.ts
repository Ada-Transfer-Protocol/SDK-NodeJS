
import { AdaTPClient } from './src/client';
import * as fs from 'fs';
import * as path from 'path';
import { MessageType, PacketFlags } from './src/protocol';
import { v4 as uuidv4, stringify as uuidStringify } from 'uuid';

async function main() {
    const client = new AdaTPClient('localhost', 3000);

    // Setup Downloads Dir
    const downloadDir = path.join(__dirname, 'downloads');
    if (!fs.existsSync(downloadDir)) fs.mkdirSync(downloadDir);

    // Create Dummy File to Send
    const uploadFile = path.join(__dirname, 'upload_test.txt');
    fs.writeFileSync(uploadFile, "These are the contents of the test file.\nHello AdaTP File Transfer!");

    try {
        await client.connect();
        await client.authenticate("filebot", "secret_password");
        await client.joinRoom("files");

        console.log("Joined 'files' room. Sending file in 2 seconds...");

        setTimeout(() => {
            client.sendFile(uploadFile).catch(console.error);
        }, 2000);

        // State for incoming files: Map<FileID_String, {filename, fd, bytesWritten}>
        const activeFiles = new Map<string, { filename: string, path: string, fd: number, total: number }>();

        // Listen Loop
        while (true) {
            const pkt = await client.readNextPacket();
            if (pkt.header.flags & PacketFlags.Encrypted) {
                const decrypted = client['cryptoSession']!.decrypt(pkt);

                if (pkt.header.msgType === MessageType.FileInit) {
                    const metadata = JSON.parse(decrypted.toString());
                    const fileId = metadata.id;
                    const sender = metadata.sender || "unknown";

                    console.log(`Receiving file: ${metadata.filename} from ${sender} (Size: ${metadata.size})`);

                    const safeName = path.basename(metadata.filename);
                    const savePath = path.join(downloadDir, `${sender}_${safeName}`);
                    const fd = fs.openSync(savePath, 'w');

                    activeFiles.set(fileId, {
                        filename: safeName,
                        path: savePath,
                        fd: fd,
                        total: 0
                    });

                } else if (pkt.header.msgType === MessageType.FileChunk) {
                    // Payload: [FileID(16)][Data]
                    if (decrypted.length > 16) {
                        const fileIdBytes = decrypted.slice(0, 16);
                        const data = decrypted.slice(16);
                        const fileId = uuidStringify(fileIdBytes);

                        const active = activeFiles.get(fileId);
                        if (active) {
                            fs.writeSync(active.fd, data);
                            active.total += data.length;
                            process.stdout.write(".");
                        }
                    }
                } else if (pkt.header.msgType === MessageType.FileComplete) {
                    // Payload: [FileID(16)]
                    const fileIdBytes = decrypted.slice(0, 16);
                    const fileId = uuidStringify(fileIdBytes);

                    const active = activeFiles.get(fileId);
                    if (active) {
                        fs.closeSync(active.fd);
                        console.log(`\nDownload Complete: ${active.path} (${active.total} bytes)`);
                        activeFiles.delete(fileId);
                    }
                } else if (pkt.header.msgType === MessageType.TextMessage) {
                    console.log("Chat:", decrypted.toString());
                }
            }
        }

    } catch (e) {
        console.error(e);
        client.disconnect();
    }
}

main();
