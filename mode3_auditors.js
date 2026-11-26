// mode3_auditors.js — 데모용 감사자 프로세스(스펙 2026-11-26 ppid-account-trace §5·§9). **한 프로세스가 감사자 셋을 흉내 낸다** — 운영이라면 조각마다 다른 주체·다른 기계다.
//   MODE3_AUDITOR_DIR=.local/auditors MODE3_AUDITOR_RPC=http://127.0.0.1:8547 MODE3_TRACE_REGISTRY=0x… node mode3_auditors.js
// 하는 일: 등록부의 OpenRequested 를 지켜보다가, 요청을 본 **뒤에만** 자기 조각으로 부분 복호(D_i + DLEQ 증명)를 만들고, 냈다는 표시(noteShare 거래)를 체인에 남긴다.
// 부분 복호는 조합자(zkWrapper)가 GET /shares/:id 로 가져간다 — 이 프로세스는 auid 를 계산하지 않는다(조각 둘을 합치지 않는다).
//   MODE3_AUDITOR_ACTIVE   응답하는 감사자(기본 "1,2" — 셋 중 둘이면 열린다는 것을 보이려고 3번은 가만히 있는다)
//   MODE3_AUDITOR_AUTO     1(기본): 요청을 보면 바로 응답 · 0: POST /respond/:id 로 사람이 승인할 때만
//   MODE3_AUDITOR_SIGNERS  감사자의 체인 계정 번호(기본 "16,17,18" — 등록부를 배포할 때의 순서와 같아야 한다)
//   MODE3_AUDITOR_TOKEN    (필수, 32자 이상) 조합자(zkWrapper)와 나눠 갖는 토큰 — /health 말고는 X-Auditor-Token 헤더가 맞아야 답한다(2026-11-26 검토 I-3:
//                          부분 복호 둘과 /pk 가 있으면 누구나 조합할 수 있으므로, 같은 PC 의 다른 프로세스·브라우저가 연 페이지가 읽거나 승인을 누르지 못하게 한다)
//   MODE3_AUDITOR_CONFIRMATIONS  요청이 실린 블록 뒤로 이만큼 더 쌓인 뒤에만 응답한다(기본 0 — 데모 체인은 거래가 있을 때만 블록이 생긴다. 운영이라면 확정을 기다린다)
// 127.0.0.1 에만 듣는다. 조각의 값은 로그·응답 어디에도 내지 않는다.
// 전제(검토 I-4·M-6): 감사자는 **자기 노드가 보여 주는 체인**을 믿는다 — 노드가 요청·기록을 꾸미면 알림 없는 부분 복호가 나간다. 운영이라면 감사자마다 자기 노드를 쓰고 확정을 기다린다.
// 데모는 노드의 개발 계정으로 거래를 낸다(노드의 RPC 에 닿는 누구나 그 계정으로 낼 수 있다).
import fs from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import express from 'express';
import { ethers } from 'ethers';
import { partialDecryptTrace, partToJson, sharePublic } from './lib/mode3_trace_record.js';
import { traceRegistryAt, isAddress, listOpenRequests, traceCtx } from './lib/mode3_trace_chain.js';

const DIR = process.env.MODE3_AUDITOR_DIR || '.local/auditors';
const RPC = process.env.MODE3_AUDITOR_RPC || 'http://127.0.0.1:8547';
const REGISTRY = process.env.MODE3_TRACE_REGISTRY || '';
const PORT = Number(process.env.MODE3_AUDITOR_PORT || 5300);
const AUTO = process.env.MODE3_AUDITOR_AUTO !== '0';
const ACTIVE = (process.env.MODE3_AUDITOR_ACTIVE || '1,2').split(',').map((s) => Number(s.trim())).filter((n) => [1, 2, 3].includes(n));
const SIGNERS = (process.env.MODE3_AUDITOR_SIGNERS || '16,17,18').split(',').map((s) => Number(s.trim()));
const POLL_MS = Number(process.env.MODE3_AUDITOR_POLL_MS || 2000);
const CONF = Math.max(0, Number(process.env.MODE3_AUDITOR_CONFIRMATIONS || 0) | 0);
const TOKEN = process.env.MODE3_AUDITOR_TOKEN || '';
if (TOKEN.length < 32) { console.error('BLOCKED: MODE3_AUDITOR_TOKEN(32자 이상)이 필요하다 — 조합자와 나눠 갖는 토큰'); process.exit(2); }
if (!isAddress(REGISTRY)) { console.error('BLOCKED: MODE3_TRACE_REGISTRY(등록부 주소)가 필요하다'); process.exit(2); }

const pub = JSON.parse(fs.readFileSync(path.join(DIR, 'pk.json'), 'utf8'));
// 조각은 메모리에만 둔다(파일에서 한 번 읽는다). 감사자 i 의 조각은 shares[i].
const shares = Object.fromEntries([1, 2, 3].map((i) => { const j = JSON.parse(fs.readFileSync(path.join(DIR, `auditor${i}.json`), 'utf8')); return [i, { index: i, x: BigInt(j.x) }]; }));
// 조각 파일이 이 디렉터리의 공개 기록(pk.json 의 X_i)과 짝인가 — 다른 키의 조각이 섞여 있으면 낸 부분 복호가 전부 버려진다(검토 M-5)
for (const i of [1, 2, 3]) { const X = await sharePublic(shares[i].x), want = pub.shares.find((s) => s.index === i)?.X; if (!want || X.x.toString() !== want.x || X.y.toString() !== want.y) { console.error(`BLOCKED: 감사자 ${i} 의 조각이 pk.json 의 공개키와 다르다`); process.exit(2); } }
const provider = new ethers.JsonRpcProvider(RPC);
const registry = traceRegistryAt(REGISTRY, provider);
const CHAIN_ID = (await provider.getNetwork()).chainId;
const onchainPk = { x: (await registry.pkAudX()).toString(), y: (await registry.pkAudY()).toString() };
if (onchainPk.x !== pub.pk.x || onchainPk.y !== pub.pk.y) { console.error('BLOCKED: 등록부의 pk_aud 가 이 디렉터리의 키와 다르다 — 등록부를 다시 올리거나(scripts/mode3_trace_setup.mjs) 맞는 디렉터리를 준다'); process.exit(2); }
const signerOf = async (i) => provider.getSigner(SIGNERS[i - 1]);
for (const i of [1, 2, 3]) { const want = await registry.auditors(i - 1), have = await (await signerOf(i)).getAddress(); if (want.toLowerCase() !== have.toLowerCase()) { console.error(`BLOCKED: 감사자 ${i} 의 계정이 등록부의 주소와 다르다`); process.exit(2); } }

const parts = new Map();   // id → { [index]: part(JSON) }
const log = (s) => console.log(`${new Date().toTimeString().slice(0, 8)} ${s}`);
let busy = Promise.resolve();
/** 그 요청에 감사자 i 가 응답한다 — 체인에 요청이 있어야 하고(여기서 다시 읽는다), 이미 냈으면 그대로. */
async function respond(id, i) {
  const have = parts.get(id) ?? {};
  if (have[i]) return have[i];
  const q = await registry.requestOf(id);   // 없는 번호면 던진다 — 체인의 요청 없이는 조각을 쓰지 않는다
  if (CONF > 0 && Number(q.requestedAt) + CONF > await provider.getBlockNumber()) throw new Error('not final yet');
  const r = await registry.recordOf(q.ppid);
  const part = partToJson(await partialDecryptTrace(shares[i], { x: r.c1x, y: r.c1y }, traceCtx({ chainId: CHAIN_ID, registry: REGISTRY, id })));
  if (!((Number(q.shareBits) >> (i - 1)) & 1)) { const tx = await registry.connect(await signerOf(i)).noteShare(id, ethers.id(JSON.stringify(part))); await tx.wait(); }
  have[i] = part; parts.set(id, have);
  log(`요청 ${id}: 감사자 ${i} 가 부분 복호를 냈다`);
  return part;
}
const respondAll = (id) => (busy = busy.then(async () => { for (const i of ACTIVE) await respond(id, i); }).catch((e) => log(`WARN 요청 ${id}: ${String(e?.shortMessage ?? e?.message ?? e).slice(0, 160)}`)));
let seen = 0;
async function tick() {
  const n = Number(await registry.requestCount());
  if (CONF > 0 && seen < n) { const head = await provider.getBlockNumber(); if (Number((await registry.requestOf(seen)).requestedAt) + CONF > head) return; }   // 확정 전이면 다음에 다시 본다
  for (; seen < n; seen++) { log(`요청 ${seen} 을 봤다${AUTO ? '' : ' — 승인 대기(POST /respond/' + seen + ')'}`); if (AUTO) respondAll(seen); if (CONF > 0) { seen++; break; } }
}

const app = express();
app.get('/health', (req, res) => res.json({ ok: true, role: 'auditors', registry: REGISTRY, active: ACTIVE, auto: AUTO, seen }));
// /health 말고는 토큰이 맞아야 한다. Host 도 본다 — 브라우저의 페이지가 이름을 127.0.0.1 로 돌려(DNS 리바인딩) 읽는 길을 막는다. 사용자 지정 헤더라 교차 사이트 폼으로 승인이 눌리지도 않는다.
const tokenOk = (t) => typeof t === 'string' && t.length === TOKEN.length && timingSafeEqual(Buffer.from(t), Buffer.from(TOKEN));
app.use((req, res, next) => {
  if (!['127.0.0.1', 'localhost'].includes(req.hostname)) return res.status(421).json({ error: 'misdirected' });
  if (!tokenOk(req.get('X-Auditor-Token'))) return res.status(401).json({ error: 'unauthorized' });
  next();
});
app.get('/pk', (req, res) => res.json({ pk: pub.pk, shares: pub.shares }));   // 공개키와 조각 공개키(X_i)뿐이다
app.get('/requests', async (req, res) => { try { res.json({ requests: (await listOpenRequests(registry)).map((q) => ({ ...q, ready: Object.keys(parts.get(q.id) ?? {}).map(Number) })) }); } catch (e) { res.status(502).json({ error: e.message }); } });
app.get('/shares/:id', (req, res) => { const id = Number(req.params.id), have = parts.get(id); if (!Number.isInteger(id) || !have) return res.status(404).json({ error: 'no shares', reason: 'trace_shares_short' }); res.json({ id, parts: Object.values(have) }); });
app.post('/respond/:id', async (req, res) => { const id = Number(req.params.id); if (!Number.isInteger(id) || id < 0) return res.status(400).json({ error: 'bad id' }); await respondAll(id); res.json({ id, ready: Object.keys(parts.get(id) ?? {}).map(Number) }); });
app.listen(PORT, '127.0.0.1', () => log(`감사자(데모 — 한 프로세스가 셋을 흉내) up :${PORT} · 등록부 ${REGISTRY} · 응답 ${ACTIVE.join(',')} · ${AUTO ? '자동' : '수동'}`));
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => process.exit(0));
for (;;) { try { await tick(); } catch (e) { log(`WARN ${String(e?.shortMessage ?? e?.message ?? e).slice(0, 160)}`); } await new Promise((r) => setTimeout(r, POLL_MS)); }
