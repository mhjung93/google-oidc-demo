#!/usr/bin/env node
// 응용 체인에 바로 붙는 JS 콘솔(2026-11-26) — 버튼 대신 시연자가 직접 거래를 꺼내 보고, 증명을 복사해 root 만 바꿔 검사하고, 실제 거래로 보낸다.
//   node scripts/mode3_console.mjs                       # RPC=http://127.0.0.1:8547 EXPLORER=http://127.0.0.1:4000 SIGNER_INDEX=19
//   TRACE_REGISTRY=0x… node scripts/mode3_console.mjs    # 추적 기록 등록부(2026-11-26) — 안 주면 지갑 서버의 공개 설정(WALLET_URL/user/config)에서 읽는다. 못 읽으면 trace 도우미 없이 뜬다
// 쓰는 법(입력할 줄)은 docs/MODE3_DEMO_SCRIPT.md 의 "체인 콘솔로 옛 증명 보이기". 도우미는 lib/mode3_console.mjs — ethers·provider·me 도 함께 올라온다.
// 보낼 때 쓰는 계정은 노드의 개발 계정이다(서비스 중계자는 0·1·2 번을 쓴다 — 겹치지 않게 19 번). 사용자 키는 쓰지 않는다.
import repl from 'node:repl';
import fs from 'node:fs';
import https from 'node:https';
import { ethers } from 'ethers';
import { createConsoleHelpers } from '../lib/mode3_console.mjs';

const RPC = process.env.RPC || 'http://127.0.0.1:8547';
const EXPLORER = process.env.EXPLORER || 'http://127.0.0.1:4000';
const provider = new ethers.JsonRpcProvider(RPC);
const me = await provider.getSigner(Number(process.env.SIGNER_INDEX ?? 19));
// 추적 기록 등록부의 주소: 환경변수, 없으면 지갑 서버의 공개 설정(데모 CA 의 공개 인증서로 확인 — 키는 읽지 않는다). 3초 안에 못 읽으면 없이 뜬다.
const WALLET_URL = (process.env.WALLET_URL || 'https://zkwrapper.zkd.test:5100').replace(/\/+$/, ''), CA_FILE = process.env.ZKD_CA_CERT || '.local/zkd-ca/ca.crt';
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const registryFromWallet = () => new Promise((resolve) => {
  try {
    const q = https.get(`${WALLET_URL}/user/config`, { ...(fs.existsSync(CA_FILE) ? { ca: fs.readFileSync(CA_FILE) } : {}), timeout: 3000 }, (r) => { let d = ''; r.on('data', (c) => { d += c; }); r.on('end', () => { try { resolve(JSON.parse(d)?.trace?.registry ?? null); } catch { resolve(null); } }); });
    q.on('timeout', () => { q.destroy(); resolve(null); }); q.on('error', () => resolve(null));
  } catch { resolve(null); }
});
const TRACE = isAddr(process.env.TRACE_REGISTRY) ? process.env.TRACE_REGISTRY : await registryFromWallet();
const helpers = createConsoleHelpers({ provider, signer: me, explorer: EXPLORER, traceRegistry: isAddr(TRACE) ? TRACE : null });
const net = await provider.getNetwork();

const HELP = `체인 ${RPC} (chainId ${net.chainId}) · 보내는 계정 ${await me.getAddress()} · 탐색기 ${EXPLORER}
  x = await tx('0x…거래 해시')     execute 거래를 풀어 증명 a·b·c, 공개 입력 pub(29), payload, 서명을 꺼낸다
  x = await last()                  가장 최근에 성공한 execute 거래
  console.log(show(x))              공개 입력을 이름과 함께 ([6] REV_ROOT = 폐기 목록 root)
  await roots(x)                    지금 체인의 root 와 증명에 든 root
  await verify(x)                   체인의 검증 컨트랙트로 그 증명 그대로 검사 → true
  y = withRoot(x, (await roots(x)).revRootNow)   증명은 그대로, root 만 바꾼 사본
  await verify(y)                   → false (증명이 root 에 묶여 있다)
  await send(x)                     실제 거래로 다시 보낸다 → reverted, NonceMismatch (이미 쓴 nonce)
  help()                            이 안내${isAddr(TRACE) ? `
 추적 기록(등록부 ${TRACE})
  r = await traceRecord(x)          그 거래의 PPID 가 남긴 추적 기록 — 체인에 있는 것은 감사자 키로 잠근 값(c1·c2)뿐이다 (PPID 를 직접 줘도 된다)
  await traceRequest(x, '사유')     개봉 요청 거래를 이 계정으로 낸다 → 그 사용자의 화면("개봉 알림")에 뜬다. 누구나 낼 수 있지만 흔적이 남는다
  await traceRequests()             체인의 개봉 요청들과 응답한 감사자(shares)` : `
 (추적 기록 등록부 주소를 읽지 못했다 — TRACE_REGISTRY=0x… 로 주면 trace 도우미가 함께 뜬다)`}`;
console.log(HELP);
const r = repl.start({ prompt: 'zkd> ' });
Object.assign(r.context, { ethers, provider, me, ...helpers, help: () => console.log(HELP) });
