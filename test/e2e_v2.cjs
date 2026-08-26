'use strict';
/**
 * End-to-end v2 authenticated handshake: this Node client against the real
 * Rust reference server, over a live WebSocket — including the header-as-AAD
 * binding and the ADATP_MIN_PROTOCOL_VERSION downgrade floor.
 *
 *   positive: pin the server's real key  -> handshake completes, an encrypted
 *             request/response round-trips (only works if BOTH the v2 signature
 *             check AND the AAD-bound AEAD agree end to end).
 *   negative: pin the WRONG key          -> the client refuses (unknown_identity).
 *   floor:    server with MIN=2 rejects a v1 (unauthenticated) client, but still
 *             accepts a pinned v2 client — the downgrade defense.
 *
 * The server binary is found via ADATP_SERVER_BIN or default paths; if it isn't
 * present the test SKIPS (exit 0). Run: `npm run build && node test/e2e_v2.cjs`
 */
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { AdaTPClient, AdaTPHandshakeError } = require('../dist/index.js');

// Server identity seed 0x11*32 -> this Ed25519 public key (also the golden vector).
const SEED = Buffer.alloc(32, 0x11);
const PINNED_PUBKEY = 'd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737';

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
const servers = [];
const tmpDirs = [];

async function startServer(bin, port, extraEnv) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'adatp-e2e-'));
    tmpDirs.push(tmp);
    const idPath = path.join(tmp, 'identity.key');
    fs.writeFileSync(idPath, SEED);
    const proc = spawn(bin, [], {
        env: {
            ...process.env,
            PORT: String(port), HOST: '127.0.0.1', AUTH_DRIVER: 'none',
            DATABASE_URL: `sqlite:${path.join(tmp, 'e2e.db')}`,
            ADATP_IDENTITY_PATH: idPath, MSG_RATE_LIMIT: '0', RUST_LOG: 'info',
            ...extraEnv,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    servers.push(proc);
    let log = '';
    proc.stdout.on('data', (d) => { log += d; });
    proc.stderr.on('data', (d) => { log += d; });
    for (let i = 0; i < 80 && !/listening on/.test(log); i++) await sleep(50);
    assert.match(log, /listening on/, `server on :${port} did not start:\n${log}`);
    assert.ok(log.includes(PINNED_PUBKEY), `server :${port} identity mismatch:\n${log}`);
    return { proc, log };
}

function cleanup() {
    for (const s of servers) { try { s.kill('SIGKILL'); } catch {} }
    for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
}

async function main() {
    const bin = findServerBin();
    if (!bin) {
        console.log('SKIP: adatp-server binary not found (set ADATP_SERVER_BIN). Not a failure.');
        process.exit(0);
    }

    try {
        // Server A: default floor (min=1) — accepts both v1 and v2.
        await startServer(bin, 3199, {});
        console.log(`  server A up on :3199 (min=1), identity ${PINNED_PUBKEY.slice(0, 16)}…`);

        // 1. correct pin -> v2 handshake + AAD-bound encrypted round-trip.
        {
            const client = new AdaTPClient('127.0.0.1', 3199, { serverKey: PINNED_PUBKEY });
            await client.connect();
            const me = await client.authenticate('guest', '');
            assert.strictEqual(me.role, 'anonymous');
            await client.joinRoom('lobby');
            await client.disconnect();
            console.log('  ok  correct pin: v2 handshake + AAD round-trip (auth + join) succeeded');
        }

        // 2. wrong pin -> refused before any key is derived.
        {
            const client = new AdaTPClient('127.0.0.1', 3199, { serverKey: '00'.repeat(32) });
            await assert.rejects(
                () => client.connect(),
                (e) => e instanceof AdaTPHandshakeError && e.code === 'unknown_identity',
            );
            try { await client.disconnect(); } catch {}
            console.log('  ok  wrong pin rejected (unknown_identity) — MITM defense holds');
        }

        // Server B: floor = 2 — must REQUIRE authenticated v2.
        await startServer(bin, 3198, { ADATP_MIN_PROTOCOL_VERSION: '2' });
        console.log('  server B up on :3198 (min=2, v2 required)');

        // 3a. a v1 (unauthenticated) client is rejected by the floor.
        {
            const v1client = new AdaTPClient('127.0.0.1', 3198); // no serverKey -> v1
            await assert.rejects(
                () => v1client.connect(),
                /closed by server|version|protocol/i,
                'a v1 client must be rejected when the server requires v2',
            );
            try { await v1client.disconnect(); } catch {}
            console.log('  ok  min=2 server rejects the v1 (unauthenticated) handshake');
        }
        // 3b. a pinned v2 client still connects to the same server.
        {
            const v2client = new AdaTPClient('127.0.0.1', 3198, { serverKey: PINNED_PUBKEY });
            await v2client.connect();
            const me = await v2client.authenticate('guest', '');
            assert.strictEqual(me.role, 'anonymous');
            await v2client.disconnect();
            console.log('  ok  min=2 server accepts the pinned v2 client');
        }

        console.log('\nEND-TO-END v2 PASSED: Node client ↔ Rust server — authenticated handshake, header-AAD, downgrade floor.');
    } finally {
        cleanup();
    }
}

main().catch((e) => { console.error('E2E FAILED:', e); cleanup(); process.exit(1); });
