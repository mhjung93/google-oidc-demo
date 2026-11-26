#!/usr/bin/env node
// 추적 기록 등록부를 응용 체인에 올린다(스펙 2026-11-26 ppid-account-trace §9) — 감사자 키가 없으면 만들고(딜러 한 번), TraceVerifier·TraceRegistry 를 배포한다.
//   MODE3_AUDITOR_DIR=.local/auditors RPC=http://127.0.0.1:8547 node scripts/mode3_trace_setup.mjs
// 출력의 마지막 줄들: MODE3_TRACE_REGISTRY=0x…  MODE3_TRACE_VERIFIER=0x… (분리 데모 스크립트가 읽는다). 조각의 값은 출력하지 않는다.
// 감사자 키 파일(조각)은 MODE3_AUDITOR_DIR 아래 auditor1..3.json(0600)과 pk.json — 데모는 한 디렉터리에 두지만 운영이라면 감사자마다 따로 갖는다.
// 배포 계정·감사자 주소는 노드의 개발 계정이다(DEPLOYER_INDEX 15, AUDITOR_SIGNERS 16,17,18 — 서비스 중계자 0·1·2, 콘솔 19 와 겹치지 않는다).
import fs from 'node:fs';
import path from 'node:path';
import { ethers } from 'ethers';
import { readArtifact } from '../lib/mode3_onchain.js';
import { dealAuditorKey, ptToJson } from '../lib/mode3_trace_record.js';

const RPC = process.env.RPC || 'http://127.0.0.1:8547';
const DIR = process.env.MODE3_AUDITOR_DIR || '.local/auditors';
const SIGNERS = (process.env.AUDITOR_SIGNERS || '16,17,18').split(',').map((s) => Number(s.trim()));
if (SIGNERS.length !== 3 || SIGNERS.some((n) => !Number.isInteger(n) || n < 0)) { console.error('AUDITOR_SIGNERS 는 계정 번호 셋(예: 16,17,18)'); process.exit(2); }

fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
const pkFile = path.join(DIR, 'pk.json'), shareFile = (i) => path.join(DIR, `auditor${i}.json`);
let pub;
// 일부만 있으면 멈춘다(2026-11-26 검토 M-5) — 조용히 새 키를 만들면 남은 조각이 덮여, 옛 키로 잠근 기록을 다시는 열지 못한다. 정말 새로 만들려면 MODE3_AUDITOR_REDEAL=yes.
const present = [pkFile, ...[1, 2, 3].map(shareFile)].filter((f) => fs.existsSync(f)).length;
if (present > 0 && present < 4 && process.env.MODE3_AUDITOR_REDEAL !== 'yes') { console.error(`BLOCKED: ${DIR} 에 감사자 키 파일이 일부만 있다(${present}/4) — 잃은 파일을 되돌리거나, 새 키로 바꾸려면 MODE3_AUDITOR_REDEAL=yes`); process.exit(2); }
if (present === 4) {
  pub = JSON.parse(fs.readFileSync(pkFile, 'utf8'));
  console.log(`감사자 키: 이미 있다(${DIR}) — 그대로 쓴다`);
} else {
  const key = await dealAuditorKey();
  for (const s of key.shares) fs.writeFileSync(shareFile(s.index), JSON.stringify({ index: s.index, x: s.x.toString(), X: ptToJson(s.X) }), { mode: 0o600 });
  pub = { pk: ptToJson(key.pk), shares: key.shares.map((s) => ({ index: s.index, X: ptToJson(s.X) })) };
  fs.writeFileSync(pkFile, JSON.stringify(pub), { mode: 0o600 });
  console.log(`감사자 키: 새로 만들었다(${DIR} — 조각 셋, 2-of-3)`);
}
const provider = new ethers.JsonRpcProvider(RPC);
const deployer = await provider.getSigner(Number(process.env.DEPLOYER_INDEX ?? 15));
const auditors = [];
for (const n of SIGNERS) auditors.push(await (await provider.getSigner(n)).getAddress());
const deploy = async (name, args) => { const a = readArtifact(name); const c = await new ethers.ContractFactory(a.abi, a.bytecode, deployer).deploy(...args); await c.waitForDeployment(); return c.getAddress(); };
const verifier = await deploy('TraceVerifier', []);
const registry = await deploy('TraceRegistry', [verifier, BigInt(pub.pk.x), BigInt(pub.pk.y), auditors]);
console.log(`chainId ${(await provider.getNetwork()).chainId} · 감사자 주소 ${auditors.join(' ')}`);
console.log(`MODE3_TRACE_VERIFIER=${verifier}`);
console.log(`MODE3_TRACE_REGISTRY=${registry}`);
