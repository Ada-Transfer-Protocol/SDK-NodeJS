'use strict';
/**
 * v2 authenticated-handshake conformance — proves this SDK's client-side crypto
 * reproduces, byte-for-byte, the same golden vectors the Rust reference server
 * emits (tests/conformance/vectors/adatp-v2-handshake-vectors.json). No server
 * needed: pure vector replay. Run: `npm run build && node test/handshake_v2.conformance.cjs`.
 */
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const {
    transcriptHash, verifyServerHello, finishedPlaintext, AdaTPHandshakeError,
} = require('../dist/handshake_v2.js');

const vectors = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'vectors', 'adatp-v2-handshake-vectors.json'), 'utf-8'),
);
const findCase = (id) => {
    const c = vectors.cases.find((c) => c.id === id);
    if (!c) throw new Error(`vector case '${id}' missing`);
    return c;
};
const hx = (s) => Buffer.from(s, 'hex');
let passed = 0;
const ok = (name) => { console.log(`  ok  ${name}`); passed++; };

// 1. transcript hash
{
    const c = findCase('handshake-v2-transcript-hash');
    const th = transcriptHash(hx(c.input.epk_c_hex), hx(c.input.epk_s_hex), hx(c.input.spk_s_hex));
    assert.strictEqual(th.toString('hex'), c.expected.transcript_hash_hex);
    ok('transcript hash matches Rust reference');
}

// 2. signed ServerHello verifies against the pinned key
{
    const c = findCase('handshake-v2-server-hello');
    const tc = findCase('handshake-v2-transcript-hash');
    const pinned = hx(tc.input.spk_s_hex); // the server's long-term public key
    const v = verifyServerHello(pinned, hx(c.input.epk_c_hex), hx(c.expected.server_hello_hex));
    assert.strictEqual(v.epkS.toString('hex'), c.input.epk_s_hex);
    assert.strictEqual(v.transcriptHash.toString('hex'), tc.expected.transcript_hash_hex);
    ok('signed ServerHello accepted; epk_s + th recovered');
}

// 3. wrong pin is rejected as unknown identity
{
    const c = findCase('handshake-v2-server-hello-wrong-pin');
    assert.throws(
        () => verifyServerHello(hx(c.input.pinned_spk_s_hex), hx(c.input.epk_c_hex), hx(c.input.server_hello_hex)),
        (e) => e instanceof AdaTPHandshakeError && e.code === 'unknown_identity',
    );
    ok('wrong pinned key rejected (unknown_identity)');
}

// 4. substituted ephemeral breaks the signature (pin passes, sig fails)
{
    const c = findCase('handshake-v2-server-hello-tampered-ephemeral');
    assert.throws(
        () => verifyServerHello(hx(c.input.pinned_spk_s_hex), hx(c.input.epk_c_hex), hx(c.input.server_hello_hex)),
        (e) => e instanceof AdaTPHandshakeError && e.code === 'signature_verification_failed',
    );
    ok('substituted ephemeral rejected (signature_verification_failed)');
}

// 5. malformed length is rejected
{
    assert.throws(
        () => verifyServerHello(Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(127)),
        (e) => e instanceof AdaTPHandshakeError && e.code === 'malformed_server_hello',
    );
    ok('malformed response length rejected');
}

// 6. Finished plaintext
{
    const c = findCase('handshake-v2-finished');
    const fin = finishedPlaintext(hx(c.input.transcript_hash_hex));
    assert.strictEqual(fin.toString('hex'), c.expected.finished_plaintext_hex);
    ok('Finished plaintext matches Rust reference');
}

console.log(`\nv2 handshake conformance: ${passed}/6 vectors passed (byte-identical to the Rust reference).`);
