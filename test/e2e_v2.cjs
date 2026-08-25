'use strict';
/**
 * End-to-end v2 authenticated handshake: this Node client against the real
 * Rust reference server, over a live WebSocket — including the header-as-AAD
 * binding. Proves the two independent implementations interoperate on the wire.
 *
 *   positive: pin the server's real key  -> handshake completes, an encrypted
 *             request/response round-trips (which only works if BOTH the v2
 *             signature check AND the AAD-bound AEAD agree end to end).
 *   negative: pin the WRONG key          -> the client refuses (unknown_identity).
 *
 * The server binary is found via ADATP_SERVER_BIN or a couple of default paths;
 * if it isn't present the test SKIPS (exit 0) so SDK-only CI is unaffected.
 * Run: `npm run build && node test/e2e_v2.cjs`
 */
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { AdaTPClient, AdaTPHandshakeError } = require('../dist/index.js');

// The server identity seed 0x11*32 yields this Ed25519 public key (the value
// pinned below and in the golden vectors). Writing the seed makes the server's
// identity deterministic, so the client can pin a known key.
const SEED = Buffer.alloc(32, 0x11);
const PINNED_PUBKEY = 'd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737';
const PORT = 3199;

function findServerBin() {
    const candidates = [
        process.env.ADATP_SERVER_BIN,
        path.resolve(__dirname, '../../../server/target/debug/adatp-server'),
        path.resolve(__dirname, '../../../target/debug/adatp-server'),
        '/Users/thecoder/adatp/server/target/debug/adatp-server',
    ].filter(Boolean);
    return candidates.find((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
    const bin = findServerBin();
    if (!bin) {
        console.log('SKIP: adatp-server binary not found (set ADATP_SERVER_BIN). Not a failure.');
        process.exit(0);
    }

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'adatp-e2e-'));
    const idPath = path.join(tmp, 'identity.key');
    fs.writeFileSync(idPath, SEED);
    const dbPath = path.join(tmp, 'e2e.db');

    const server = spawn(bin, [], {
        env: {
            ...process.env,
            PORT: String(PORT),
            HOST: '127.0.0.1',
            AUTH_DRIVER: 'none',
            DATABASE_URL: `sqlite:${dbPath}`,
            ADATP_IDENTITY_PATH: idPath,
            MSG_RATE_LIMIT: '0',
            RUST_LOG: 'info',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    let serverLog = '';
    server.stdout.on('data', (d) => { serverLog += d; });
    server.stderr.on('data', (d) => { serverLog += d; });

    const cleanup = () => {
        try { server.kill('SIGKILL'); } catch {}
        try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    };

    try {
        // Wait for the server to be listening (and confirm it loaded our pinned key).
        for (let i = 0; i < 80 && !/listening on/.test(serverLog); i++) await sleep(50);
        assert.match(serverLog, /listening on/, `server did not start:\n${serverLog}`);
        assert.ok(serverLog.includes(PINNED_PUBKEY),
            `server identity is not the expected pinned key:\n${serverLog}`);
        console.log(`  server up on :${PORT}, identity ${PINNED_PUBKEY.slice(0, 16)}…`);

        // ---- positive: correct pin -> v2 handshake + encrypted round-trip ----
        {
            const client = new AdaTPClient('127.0.0.1', PORT, { serverKey: PINNED_PUBKEY });
            await client.connect(); // v2 handshake (signature verify + AAD-bound Finished)
            // An encrypted request/response round-trip: only succeeds if the AAD-bound
            // AEAD session agrees in BOTH directions.
            const me = await client.authenticate('guest', '');
            assert.strictEqual(me.role, 'anonymous', 'none-driver returns anonymous');
            await client.joinRoom('lobby');
            await client.disconnect();
            console.log('  ok  correct pin: v2 handshake + AAD round-trip (auth + join) succeeded');
        }

        // ---- negative: wrong pin -> client refuses before deriving keys ----
        {
            const wrong = '00'.repeat(32);
            const client = new AdaTPClient('127.0.0.1', PORT, { serverKey: wrong });
            await assert.rejects(
                () => client.connect(),
                (e) => e instanceof AdaTPHandshakeError && e.code === 'unknown_identity',
                'a wrong pinned key must be rejected as unknown_identity',
            );
            try { await client.disconnect(); } catch {}
            console.log('  ok  wrong pin rejected (unknown_identity) — MITM defense holds');
        }

        console.log('\nEND-TO-END v2 PASSED: Node client ↔ Rust server, authenticated handshake + header-AAD.');
    } finally {
        cleanup();
    }
}

main().catch((e) => { console.error('E2E FAILED:', e); process.exit(1); });
