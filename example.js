const { AdaTPClient } = require('./dist/index');

async function run() {
    console.log("Starting AdaTP JS Client...");

    // Create client instance
    const client = new AdaTPClient('127.0.0.1', 8443);

    try {
        console.log("Attempting to connect...");
        await client.connect();

        console.log("Connection established! Sending message...");
        await client.sendTextMessage("Hello from pure JavaScript!");

        console.log("Disconnecting...");
        await client.disconnect();
    } catch (err) {
        console.error("Client error:", err);
    }
}

run();
