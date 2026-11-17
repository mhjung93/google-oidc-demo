// lib/mode3_tls.js — 선택적 TLS 기동(passkey-web Task 1). 외부 의존 없음(openssl 만). (unit 그룹)
//   node tests/test_mode3_tls.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { spawnSync } from 'node:child_process';
import express from 'express';
import { tlsOptionsFromEnv, listenMaybeTls } from '../lib/mode3_tls.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-tls-'));
const c = path.join(dir, 'c.pem');
const k = path.join(dir, 'k.pem');
const gen = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
  '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', k, '-out', c], { stdio: 'pipe' });
if (gen.status !== 0) { console.error('BLOCKED: openssl 로 시험용 인증서를 만들 수 없다'); process.exit(1); }

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const get = (mod, opts) => new Promise((resolve, reject) => {
  const r = mod.get({ host: '127.0.0.1', path: '/x', timeout: 3000, ...opts }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  r.on('error', reject);
  r.on('timeout', () => r.destroy(new Error('timeout')));
});
const start = (env) => new Promise((resolve) => {
  const app = express();
  app.get('/x', (_req, res) => res.json({ ok: true }));
  const { server, scheme } = listenMaybeTls(app, { port: 0, host: '127.0.0.1', env, onListening: () => resolve({ server, scheme, port: server.address().port }) });
});
const stop = (s) => new Promise((r) => { s.closeAllConnections?.(); s.close(() => r()); });

await t('env 없음 → http', async () => {
  const s = await start({});
  try { assert.equal(s.scheme, 'http'); assert.equal(await get(http, { port: s.port }), 200); } finally { await stop(s.server); }
});
await t('cert·key → https, 같은 포트에 http 는 거부', async () => {
  const s = await start({ MODE3_TLS_CERT: c, MODE3_TLS_KEY: k });
  try {
    assert.equal(s.scheme, 'https');
    assert.equal(await get(https, { port: s.port, ca: fs.readFileSync(c) }), 200);
    await assert.rejects(get(http, { port: s.port }));
  } finally { await stop(s.server); }
});
await t('하나만 주면 거부', () => {
  assert.throws(() => tlsOptionsFromEnv({ MODE3_TLS_CERT: c }), /함께/);
  assert.throws(() => tlsOptionsFromEnv({ MODE3_TLS_KEY: k }), /함께/);
});
await t('없는 파일 → 경로만 담긴 오류', () => {
  const p = path.join(dir, 'none.pem');
  assert.throws(() => tlsOptionsFromEnv({ MODE3_TLS_CERT: p, MODE3_TLS_KEY: k }), (e) => e.message.includes(p) && !e.message.includes('BEGIN'));
});
fs.rmSync(dir, { recursive: true, force: true });
process.exit(failed === 0 ? 0 : 1);
