// IdP가 크레덴셜 유효기간(max_height)에 상한을 강제하는지 검사한다.
//   node tests/test_max_height_bound.js   (custom_idp.js:4000, server.js:3000, wallet_agent.js:5001 필요)
//
// 왜 필요한가 (2026-09-04 전체 코드 리뷰).
//
// max_height는 전적으로 지갑이 정한다(wallet_agent.js: currentBlock + validityWindowBlocks()).
// IdP는 증명 신호와의 일치만 볼 뿐 "지금 블록 대비 얼마나 먼 미래인가"를 보지 않았다.
// 그런데 계정 폐기 리프의 만료는 접수 시점 + CREDENTIAL_LIFETIME_BLOCKS(300)로 고정된다.
//
// 그래서 수정된 지갑이 max_height = currentBlock + 100000짜리 토큰을 받아두면:
//   1) 운영자가 그 계정을 폐기한다 → 리프 만료 = 지금 + 300
//   2) 300블록 뒤 재기준화가 그 리프를 "만료"로 회수한다
//   3) 아직 유효한 pi_pk_i 증명이 계정 비멤버십을 다시 통과한다
//      → 폐기된 계정이 약 99,700블록 동안 지갑 전권을 되찾는다
// 계정 폐기는 disabled를 세우지 않으므로 이 경로를 막는 것이 없다. PPIDWallet.execute의
// block.number > max_height 만료 검사도 사실상 무한이 된다.
//
// 검사 방법: /par는 호출자가 준 public signals를 그대로 보관하므로, 정직한 증명에
// max_height 신호만 부풀려 밀어넣고 /authorize/login의 거부 사유를 본다. 상한 검사는
// 비싼 groth16 검증보다 **앞에** 있어야 한다(싼 검사가 먼저다 — 기존 코드의 원칙).
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';

const IDP = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';
const RPC = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';

// custom_idp.js와 같은 값이어야 한다(TOKEN_VALIDITY_SECONDS 3600 / ETHEREUM_SLOT_SECONDS 12).
const CREDENTIAL_LIFETIME_BLOCKS = 300n;

async function currentBlock() {
  const r = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
  });
  return BigInt((await r.json()).result);
}

async function honestStep8() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
  const step8 = await (
    await fetch(`${WALLET}/generateStep8Proofs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
      body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
    })
  ).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);
  return step8;
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(sk_i, false);
  const pk_i = `0x${keccak256('0x' + Buffer.from(pub.slice(1)).toString('hex')).slice(-40)}`;
  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]),
  );
  const raw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature =
    '0x' +
    raw.r.toString(16).padStart(64, '0') +
    raw.s.toString(16).padStart(64, '0') +
    (27 + raw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function pushAndLogin(step8, publicSignals) {
  const state = `mh-state-${Date.now()}`;
  const nonce = `mh-nonce-${Date.now()}`;
  const code_challenge = 'dGVzdC1jaGFsbGVuZ2U';
  const par = await (
    await fetch(`${IDP}/par`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: 'pairct-wallet',
        redirect_uri: 'http://127.0.0.1:49999/oidc/callback',
        response_type: 'code',
        state,
        nonce,
        code_challenge,
        code_challenge_method: 'S256',
        zkpProof: step8.zkpProof,
        zkpPublicSignals: publicSignals,
        chain_id: step8.chain_id,
        requestBinding: signBinding(state, nonce, code_challenge),
      }),
    })
  ).json();
  if (!par.request_uri) throw new Error(`/par rejected the request: ${JSON.stringify(par)}`);

  const res = await fetch(`${IDP}/authorize/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, username: 'testuser', password: 'password123' }),
  });
  return { status: res.status, body: await res.json() };
}

const step8 = await honestStep8();
// zkpPublicSignals는 uid를 뺀 7개다(IdP가 세션 uid를 앞에 붙여 검증한다).
// 순서: [arid_i, auid_i, max_height, token_nonce, auid, pk_IdP_x, pk_IdP_y]
const MAX_HEIGHT_INDEX = 2;

const honestMaxHeight = BigInt(step8.zkpPublicSignals[MAX_HEIGHT_INDEX]);
const block = await currentBlock();
assert.ok(
  honestMaxHeight <= block + CREDENTIAL_LIFETIME_BLOCKS + 64n,
  `준비: 지갑이 만든 max_height가 정상 범위여야 한다 (block ${block}, max_height ${honestMaxHeight})`,
);
console.log(`OK (준비): 정직한 max_height = ${honestMaxHeight} (현재 블록 ${block})`);

// --- 부풀린 max_height는 거부돼야 한다 ---------------------------------------
const inflated = [...step8.zkpPublicSignals];
inflated[MAX_HEIGHT_INDEX] = (block + 100000n).toString();

const { status, body } = await pushAndLogin(step8, inflated);
assert.equal(status, 400, `부풀린 max_height는 400이어야 한다 (받은 코드 ${status})`);
assert.match(
  String(body.error ?? ''),
  /max_height/i,
  `거부 사유가 max_height 상한임을 알 수 있어야 한다. 받은 메시지: ${JSON.stringify(body)}\n` +
    '(증명 검증 실패로 거부되는 것으로는 부족하다 — 상한 검사가 없으면 유효한 증명을 가진 ' +
    '수정된 지갑은 그대로 통과한다.)',
);
console.log('OK: 상한을 넘는 max_height가 거부된다 —', body.error);

console.log('PASS: IdP가 크레덴셜 유효기간 상한을 강제한다.');
