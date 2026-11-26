#!/usr/bin/env node
// 응용 체인에 바로 붙는 JS 콘솔(2026-11-26) — 버튼 대신 시연자가 직접 거래를 꺼내 보고, 증명을 복사해 root 만 바꿔 검사하고, 실제 거래로 보낸다.
//   node scripts/mode3_console.mjs                       # RPC=http://127.0.0.1:8547 EXPLORER=http://127.0.0.1:4000 SIGNER_INDEX=19
// 쓰는 법(입력할 줄)은 docs/MODE3_DEMO_SCRIPT.md 의 "체인 콘솔로 옛 증명 보이기". 도우미는 lib/mode3_console.mjs — ethers·provider·me 도 함께 올라온다.
// 보낼 때 쓰는 계정은 노드의 개발 계정이다(서비스 중계자는 0·1·2 번을 쓴다 — 겹치지 않게 19 번). 사용자 키는 쓰지 않는다.
import repl from 'node:repl';
import { ethers } from 'ethers';
import { createConsoleHelpers } from '../lib/mode3_console.mjs';

const RPC = process.env.RPC || 'http://127.0.0.1:8547';
const EXPLORER = process.env.EXPLORER || 'http://127.0.0.1:4000';
const provider = new ethers.JsonRpcProvider(RPC);
const me = await provider.getSigner(Number(process.env.SIGNER_INDEX ?? 19));
const helpers = createConsoleHelpers({ provider, signer: me, explorer: EXPLORER });
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
  help()                            이 안내`;
console.log(HELP);
const r = repl.start({ prompt: 'zkd> ' });
Object.assign(r.context, { ethers, provider, me, ...helpers, help: () => console.log(HELP) });
