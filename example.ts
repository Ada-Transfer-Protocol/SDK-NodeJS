import { AdaTPClient } from './src/client';
import * as readline from 'readline';

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const ask = (q: string): Promise<string> => new Promise(resolve => rl.question(q, resolve));

    console.log("==========================================");
    console.log("   AdaTP Node.js Chat Client (CLI)       ");
    console.log("==========================================");

    const username = await ask("Enter your username: ");
    const password = await ask("Enter your password (default: secret_password): ") || "secret_password";
    const client = new AdaTPClient('127.0.0.1', 3000);

    try {
        console.log("Connecting...");
        await client.connect();

        console.log("Authenticating...");
        await client.authenticate(username, password);

        // Setup Message Handler
        client.setMessageHandler((sender: string, text: string) => {
            // Check if text is from self? Server echoes back everything.
            // If sender logic is not implemented in server, we get raw text.
            // PHP client adds [User] prefix.
            // If we receive "[User] ...", print it.
            // If we receive raw text, print it.
            // Avoid printing own messages if possible? 
            // Server broadcasts to ALL, including sender.
            // Simple approach: Print everything except if it starts with "[MyUsername]"?
            // But let's just print everything for transparency like PHP example.

            // Clear current line to avoid mess with prompt?
            // readline.cursorTo(process.stdout, 0); 
            console.log(`< ${text}`);
            // rl.prompt(true);
        });

        console.log(`Joined chat as '${username}'.`);
        console.log("Type '/join <room>' to switch rooms.");
        console.log("Type '/quit' to exit.");

        rl.on('line', async (line) => {
            const input = line.trim();
            if (!input) return;

            if (input === '/quit') {
                console.log("Exiting...");
                await client.disconnect();
                process.exit(0);
            }

            if (input.startsWith('/join ')) {
                const room = input.substring(6).trim();
                if (room) {
                    await client.joinRoom(room);
                    console.log(`Joined room: ${room}`);
                }
                return;
            }

            // Send Chat
            const msg = `[${username}] ${input}`;
            await client.sendTextMessage(msg);
        });

    } catch (e) {
        console.error("Connection Error:", e);
        process.exit(1);
    }
}

main();
