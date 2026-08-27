// Mode 2 폐기(revocation) 전 구간 온체인 E2E 테스트.
//
// 이 테스트가 처음으로 검증하는 것: 살아있는 wallet_agent가 만든 '진짜' pi_pk_i 증명이
// 실제로 배포된 PPIDWallet.execute()를 통과하고(구간 A), 폐기 이후에는 지갑이 스스로
// 증명 생성을 거부하며(구간 B), 만료된 폐기 root로는 체인이 트랜잭션을 거부한다는 것
// (구간 C). 기존 test/PPIDWalletRevocation.test.mjs는 all-zero mock 증명으로 early
// revert하는 negative path만 봤기 때문에, verifier를 실제로 통과하는 경로는 이 브랜치에서
// 한 번도 확인된 적이 없었다.
//
// == 전제 조건 ==
//   - custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001),
//     hardhat node (:8545) 가 모두 실행 중이어야 한다.
//   - 환경변수 IDP_ADMIN_SECRET: /idp/revoke 관리자 인증용. 실행 중인 IdP가 떠 있는
//     값과 같아야 한다. 예:
//       IDP_ADMIN_SECRET=... node tests/test_mode2_e2e_onchain.js
//   - 환경변수 REVOCATION_REGISTRY_ADDRESS / PPID_WALLET_FACTORY_ADDRESS 는 생략 시
//     아래 기본값(현재 배포 주소)을 쓴다. RevocationRegistry의 운영자 주소는
//     하드코딩하지 않고 배포된 컨트랙트의 idp() getter에서 읽는다.
//
// == 이 테스트는 환경을 변경한다 ==
//   - 체인 블록을 GRACE_BLOCKS+1 (201) 개 진행시킨다.
//   - IdP 폐기 트리에 이 실행에서 발급받은 세션의 r_token 리프를 1개 추가한다(되돌릴 수 없음).
//   - RevocationRegistry에 root를 여러 번 게시한다.
//   마지막에 root를 재게시해 isRecentRoot가 다시 true가 되도록 환경을 복구하고,
//   복구 여부를 단언한다. 이 복구를 빠뜨리면 이후 모든 정상 트랜잭션이
//   StaleRevocationRoot로 막힌다.
//
// == 멱등성 ==
//   이 테스트는 멱등이 아니지만 재실행은 안전하다. 매 실행마다 새로 로그인해서
//   새 r_token을 발급받으므로, 폐기 대상 리프가 항상 새 값이고 IdP root가 반드시
//   바뀐다(같은 값을 다시 폐기해 root가 안 바뀌는 no-op 상황이 생기지 않는다).
//   누적되는 부작용은 폐기 트리에 리프가 1개씩 쌓이는 것과 체인이 201블록씩
//   진행되는 것뿐이고, 둘 다 이후 실행의 결과를 바꾸지 않는다.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  keccak256,
  AbiCoder,
  Interface,
  Contract,
  JsonRpcProvider,
  Wallet,
  NonceManager,
} from 'ethers';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';
const RPC = 'http://127.0.0.1:8545';

const REGISTRY_ADDRESS =
  process.env.REVOCATION_REGISTRY_ADDRESS || '0x7a2088a1bFc9d81c55368AE168C2C02570cB814F';

// hardhat 기본 니모닉의 0번 계정. 로컬 데모 체인에서 가스비를 낼 자금이 있는 계정으로,
// 브라우저의 MetaMask가 하던 역할(배포/execute 트랜잭션 전송)을 대신한다.
const HARDHAT_ACCOUNT0_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const REGISTRY_ABI = [
  'function idp() view returns (address)',
  'function filled() view returns (uint256)',
  'function latestRoot() view returns (bytes32)',
  'function GRACE_BLOCKS() view returns (uint256)',
  'function isRecentRoot(bytes32) view returns (bool)',
];

// PPIDWallet.execute()가 되돌릴 수 있는 커스텀 에러들. revert 사유를 이름으로
// 판정하기 위해 필요하다 — "revert 했다"만으로는 어느 검사에 걸렸는지 알 수 없다.
const WALLET_ERRORS = new Interface([
  'error NonceMismatch(uint256 expected, uint256 got)',
  'error BadSignature()',
  'error UntrustedIdP()',
  'error InvalidProof()',
  'error Expired(uint256 currentBlock, uint256 maxHeight)',
  'error StaleRevocationRoot(bytes32 root)',
]);

function requireAdminSecret() {
  const secret = process.env.IDP_ADMIN_SECRET;
  if (!secret) {
    throw new Error(
      'IDP_ADMIN_SECRET 환경변수가 필요합니다(/idp/revoke 관리자 인증). ' +
        '실행 중인 custom_idp.js가 떠 있는 값과 같아야 합니다.',
    );
  }
  return secret;
}

// --- 로그인 흐름 (tests/test_par_authorize_token_e2e.js의 testNewFlow와 동일) -------

async function getWalletAgentToken() {
  const res = await fetch(`${SERVER}/api/mode2/wallet_agent_token`);
  if (!res.ok) throw new Error(`/api/mode2/wallet_agent_token failed: ${res.status}`);
  return (await res.json()).token;
}

function signBinding(state, nonce, codeChallenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const addressBytes = keccak256(
    '0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex'),
  ).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(
      ['string', 'string', 'string'],
      [state, nonce, codeChallenge],
    ),
  );
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature =
    '0x' +
    sigRaw.r.toString(16).padStart(64, '0') +
    sigRaw.s.toString(16).padStart(64, '0') +
    (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function loginAndIssueStatement() {
  const registration = await (
    await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })
  ).json();
  const walletAgentToken = await getWalletAgentToken();

  const rpNonce = '222';
  const step8 = await (
    await fetch(`${WALLET}/generateStep8Proofs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Wallet-Agent-Token': walletAgentToken,
        Origin: SERVER,
      },
      body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce }),
    })
  ).json();
  if (!step8.zkpProof) throw new Error(`/generateStep8Proofs failed: ${JSON.stringify(step8)}`);

  const state = 'e2e-onchain-state';
  const nonce = 'e2e-onchain-nonce';
  const redirectUri = 'http://127.0.0.1:49997/oidc/callback';
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  const par = await (
    await fetch(`${IDP}/par`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: 'pairct-wallet',
        redirect_uri: redirectUri,
        response_type: 'code',
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        zkpProof: step8.zkpProof,
        zkpPublicSignals: step8.zkpPublicSignals,
        chain_id: step8.chain_id,
        requestBinding: signBinding(state, nonce, codeChallenge),
      }),
    })
  ).json();
  if (!par.request_uri) throw new Error(`/par failed: ${JSON.stringify(par)}`);

  const login = await (
    await fetch(`${IDP}/authorize/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request_uri: par.request_uri,
        username: 'testuser',
        password: 'password123',
      }),
    })
  ).json();
  if (!login.success) throw new Error(`/authorize/login failed: ${JSON.stringify(login)}`);

  const consent = await (
    await fetch(`${IDP}/authorize/consent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_uri: par.request_uri, allowed: true }),
    })
  ).json();
  const code = new URL(consent.redirectTo).searchParams.get('code');
  if (!code) throw new Error(`/authorize/consent failed: ${JSON.stringify(consent)}`);

  const statement = await (
    await fetch(`${IDP}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'pairct-wallet',
        code_verifier: codeVerifier,
      }),
    })
  ).json();
  if (!statement.signature) throw new Error(`/token failed: ${JSON.stringify(statement)}`);

  return { step8, statement, rpNonce, walletAgentToken };
}

// --- /submitTransaction (client.js:444-463이 보내는 형태를 그대로 미러링) ----------

async function submitTransaction({ step8, statement, rpNonce, walletAgentToken }) {
  // /token 응답은 새 9-field statement 안에 옛 6-field idpToken을 중첩해 내려준다.
  // /submitTransaction이 소비하는 것은 그 중첩된 idpToken 쪽이다.
  const { idpToken, ...statementFields } = statement;
  const res = await fetch(`${WALLET}/submitTransaction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': walletAgentToken },
    body: JSON.stringify({
      to: '0x000000000000000000000000000000000000dEaD',
      value: '0',
      data: '0x',
      business: {
        arid_i: String(step8.arid_i),
        auid_i: String(step8.auid_i),
        ppid: String(step8.ppid),
        r_token: statementFields.r_token,
        chain_id: statementFields.chain_id,
        maxHeight: statementFields.max_height,
      },
      rpNonce,
      idpToken,
    }),
  });
  return { status: res.status, body: await res.json() };
}

// --- 온체인 헬퍼 -------------------------------------------------------------

function rootToBytes32(root) {
  return '0x' + BigInt(root).toString(16).padStart(64, '0');
}

// provider.getBlockNumber()는 ethers가 polling 간격 동안 값을 캐시하기 때문에
// hardhat_mine 직후에 부르면 진행 전 높이를 그대로 돌려준다. 채굴 전후를 비교하는
// 용도로는 캐시를 타지 않는 raw eth_blockNumber를 쓴다.
async function currentBlockNumber(provider) {
  return Number(await provider.send('eth_blockNumber', []));
}

async function fetchIdpRoot() {
  const res = await fetch(`${IDP}/idp/revocation_state`);
  if (!res.ok) throw new Error(`/idp/revocation_state failed: ${res.status}`);
  return String((await res.json()).root);
}

// push_revocation_root.cjs는 반드시 `npx hardhat run ... --network localhost`로 돌려야
// 한다. `node`로 실행하면 defaultNetwork가 "hardhat"이라 명령 종료와 함께 사라지는
// 임시 인프로세스 체인에 게시된다(스크립트 안에 가드가 있다).
function pushRevocationRoot(idpOperatorAddress) {
  return execFileSync(
    'npx',
    ['hardhat', 'run', 'scripts/push_revocation_root.cjs', '--network', 'localhost'],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        REVOCATION_REGISTRY_ADDRESS: REGISTRY_ADDRESS,
        REVOCATION_IDP_ADDRESS: idpOperatorAddress,
      },
    },
  );
}

// revert 사유를 커스텀 에러 '이름'으로 뽑아낸다. ethers는 실패 지점(estimateGas /
// call / receipt)에 따라 revert 바이트를 서로 다른 자리에 담으므로 모두 훑는다.
function decodeRevertName(err) {
  const candidates = [
    err?.data,
    err?.info?.error?.data?.data,
    err?.info?.error?.data,
    err?.error?.data?.data,
    err?.error?.data,
  ];
  for (const raw of candidates) {
    const hex = typeof raw === 'string' ? raw : raw?.data;
    if (typeof hex !== 'string' || !hex.startsWith('0x') || hex.length < 10) continue;
    const parsed = WALLET_ERRORS.parseError(hex);
    if (parsed) return parsed.name;
  }
  return null;
}

async function main() {
  const adminSecret = requireAdminSecret();

  const provider = new JsonRpcProvider(RPC);
  // NonceManager로 감싸지 않으면 같은 블록 안에서 연속 전송할 때 ethers가 'latest'
  // 기준 nonce를 재사용해 "Nonce too low"로 실패한다(배포 tx 직후 execute tx).
  const signer = new NonceManager(new Wallet(HARDHAT_ACCOUNT0_PK, provider));
  const registry = new Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider);

  // GRACE_BLOCKS는 하드코딩하지 않고 배포된 레지스트리에서 읽는다.
  const graceBlocks = Number(await registry.GRACE_BLOCKS());
  // pushRoot는 onlyIdP다. 운영자 주소도 하드코딩하지 않고 온체인 getter에서 읽는다.
  const idpOperator = await registry.idp();
  console.log(`OK: registry ${REGISTRY_ADDRESS} GRACE_BLOCKS=${graceBlocks} idp=${idpOperator}`);

  // 전제조건: 구간 A는 지갑이 'IdP의 현재 root가 이미 온체인에 게시돼 있다'고
  // 가정한다. 그런데 IdP root를 바꾸면서 게시는 하지 않는 다른 테스트
  // (tests/test_idp_revoke_endpoint.js, tests/test_revocation_e2e.js)를 먼저 돌리면
  // 그 가정이 깨져, 구간 A가 검증하려는 것과 무관하게 /submitTransaction이 400으로
  // 실패한다. 자기 전제조건은 스스로 세운다 — 시작 전에 현재 root를 한 번 게시한다.
  if (!(await registry.isRecentRoot(rootToBytes32(await fetchIdpRoot())))) {
    pushRevocationRoot(idpOperator);
    assert.equal(
      await registry.isRecentRoot(rootToBytes32(await fetchIdpRoot())),
      true,
      '전제조건 실패: 게시했는데도 IdP의 현재 root가 isRecentRoot=false다',
    );
    console.log('OK: 전제조건 — IdP의 현재 root가 게시돼 있지 않아 먼저 게시했다');
  }

  // 구간 B 이후로는 블록을 진행시키므로 게시된 root가 만료된다. 도중에 실패해도
  // 환경이 망가진 채 남지 않도록 복구를 finally에 둔다 — 복구를 빼먹으면 이후
  // 모든 정상 트랜잭션이 StaleRevocationRoot로 막힌다(실제로 이 테스트를 만드는
  // 도중 중단된 실행이 그 상태를 만들었다).
  try {
    await runSections({ provider, signer, registry, graceBlocks, idpOperator, adminSecret });
  } finally {
    await restoreEnvironment({ registry, idpOperator });
  }

  console.log(
    'PASS: 폐기 전 구간 온체인 E2E — 진짜 증명이 execute()를 통과하고(A), ' +
      '폐기 후 지갑이 증명 생성을 거부하며(B), 만료된 root를 체인이 거부한다(C)',
  );
}

// 블록을 진행시킨 뒤 현재 IdP root를 재게시해 환경을 되돌린다.
async function restoreEnvironment({ registry, idpOperator }) {
  try {
    const idpRootNow = await fetchIdpRoot();
    pushRevocationRoot(idpOperator);
    assert.equal(
      await registry.isRecentRoot(rootToBytes32(idpRootNow)),
      true,
      '환경 복구 실패: 재게시했는데도 IdP의 현재 root가 isRecentRoot=false다',
    );
    console.log('OK: 환경 복구 — root를 재게시해 isRecentRoot(현재 IdP root) === true');
  } catch (err) {
    // 복구 실패는 반드시 눈에 띄어야 한다. 앞선 오류를 덮어쓰지 않도록 여기서
    // 던지지 않고 크게 출력만 한다.
    console.error(
      '치명적: 환경 복구에 실패했습니다. 게시된 폐기 root가 만료된 채로 남아 ' +
        '이후 정상 트랜잭션이 StaleRevocationRoot로 막힙니다. 수동으로 실행하세요:\n' +
        '  REVOCATION_REGISTRY_ADDRESS=... REVOCATION_IDP_ADDRESS=... ' +
        'npx hardhat run scripts/push_revocation_root.cjs --network localhost\n' +
        `원인: ${err.message}`,
    );
  }
}

async function runSections({ provider, signer, registry, graceBlocks, idpOperator, adminSecret }) {
  // ===== 구간 A — 진짜 증명이 온체인 execute()를 통과한다 =====
  const session = await loginAndIssueStatement();
  console.log(
    `OK: 로그인 완주, statement 발급 (max_height=${session.statement.max_height}, chain_id=${session.statement.chain_id})`,
  );

  const first = await submitTransaction(session);
  assert.equal(first.status, 200, `구간 A /submitTransaction 실패: ${JSON.stringify(first.body)}`);
  assert.ok(first.body.data, '구간 A: execute calldata가 비어 있다');
  console.log(`OK: calldata#1 생성 (지갑 ${first.body.to}, deploy=${first.body.deploy !== null})`);

  if (first.body.deploy) {
    const deployTx = await signer.sendTransaction({
      to: first.body.deploy.to,
      data: first.body.deploy.data,
    });
    const deployReceipt = await deployTx.wait();
    assert.equal(deployReceipt.status, 1, 'PPIDWallet 배포 트랜잭션이 실패했다');
    console.log(`OK: PPIDWallet 배포됨 (block ${deployReceipt.blockNumber})`);
  }

  const executeTx = await signer.sendTransaction({ to: first.body.to, data: first.body.data });
  const executeReceipt = await executeTx.wait();
  assert.equal(
    executeReceipt.status,
    1,
    '구간 A: 진짜 pi_pk_i 증명으로 보낸 execute()가 온체인에서 실패했다',
  );
  console.log(
    `OK: 구간 A — 실제 증명이 PPIDWallet.execute()를 통과했다 (block ${executeReceipt.blockNumber}, gas ${executeReceipt.gasUsed})`,
  );

  // ===== 구간 A' — 구간 C에서 쓸 calldata#2를 폐기 '전에' 미리 확보한다 =====
  //
  // 순서가 중요하다. PPIDWallet.execute()의 검사 순서는
  //   NonceMismatch -> BadSignature -> UntrustedIdP -> isRecentRoot -> verifyProof -> Expired
  // 이다. 구간 A의 calldata를 그대로 재전송하면 지갑 nonce 0이 이미 소비돼
  // NonceMismatch가 먼저 걸리고, 폐기 검사(isRecentRoot)에 도달조차 못 한다.
  // 여기서 미리 받아두는 calldata#2는 nonce 1로 만들어지므로 nonce 검사를 통과해
  // isRecentRoot까지 도달한다. 이 순서 없이는 구간 C가 검증하려는 것을 검증하지 못한다.
  //
  // calldata#2는 '아직 유효한 현재 root'로 만들어진다. 구간 B에서 블록을 진행시켜
  // 그 root를 만료시킨 뒤 구간 C에서 전송한다.
  const second = await submitTransaction(session);
  assert.equal(second.status, 200, `구간 A' /submitTransaction 실패: ${JSON.stringify(second.body)}`);
  assert.equal(second.body.deploy, null, "구간 A': 지갑이 이미 배포됐는데 deploy가 null이 아니다");
  const calldata2 = { to: second.body.to, data: second.body.data };
  console.log("OK: 구간 A' — calldata#2 확보 (nonce 1, 아직 유효한 root, 전송하지 않음)");

  // ===== 구간 B — 지갑이 폐기된 크레덴셜로 증명 생성을 거부한다 =====
  const revokeRes = await fetch(`${IDP}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': adminSecret },
    body: JSON.stringify({ type: 'session', value: session.statement.r_token }),
  });
  const revokeBody = await revokeRes.json();
  assert.equal(revokeRes.status, 200, `/idp/revoke 실패: ${JSON.stringify(revokeBody)}`);
  assert.ok(revokeBody.root, '/idp/revoke 응답에 새 root가 없다');
  console.log('OK: IdP가 이 세션의 r_token을 폐기했다 (새 root 발급)');

  pushRevocationRoot(idpOperator);
  assert.equal(
    await registry.isRecentRoot(rootToBytes32(revokeBody.root)),
    true,
    '폐기 후 새 root가 레지스트리에 게시되지 않았다',
  );
  console.log('OK: 폐기 후 새 root를 온체인에 게시했다');

  // 폐기 직후에도 지갑은 여전히 트랜잭션을 만들어 준다 — 이것은 버그가 아니라
  // wallet_agent.js가 의도적으로 남겨둔 grace window다. 지갑은 캐시된 pi_pk_i 증명의
  // root가 아직 레지스트리 윈도우 안에 살아있으면 그대로 재사용하고 IdP에 아무 요청도
  // 보내지 않는다(매 트랜잭션마다 IdP를 조회하면 "IdP 로그 <-> 온체인 지갑" 타이밍
  // 상관으로 지갑과 uid가 연결되기 때문). 그 대가로 폐기의 효력은 최대 GRACE_BLOCKS
  // 만큼 지연된다. 이 창의 존재 자체를 여기서 단언해 회귀를 잡는다.
  const duringGrace = await submitTransaction(session);
  assert.equal(
    duringGrace.status,
    200,
    'grace window 안에서는 캐시된 증명 재사용으로 200이 나와야 한다(의도된 동작)',
  );
  console.log(
    'OK: 폐기 직후 grace window 안에서는 캐시된 증명이 그대로 재사용된다 (의도된 지연)',
  );

  // 캐시된 root를 만료시킨다. 이제서야 지갑이 IdP에서 witness를 다시 가져오는 경로를
  // 타고, 폐기된 세션에 대해 비멤버십 witness를 만들 수 없어 스스로 멈춘다.
  // (구간 C에서 쓸 calldata#2의 root도 이 시점에 함께 만료된다.)
  const blockBeforeMine = await currentBlockNumber(provider);
  await provider.send('hardhat_mine', ['0x' + (graceBlocks + 1).toString(16)]);
  const blockAfterMine = await currentBlockNumber(provider);
  assert.ok(
    blockAfterMine - blockBeforeMine >= graceBlocks + 1,
    `블록이 충분히 진행되지 않았다: ${blockBeforeMine} -> ${blockAfterMine}`,
  );
  console.log(
    `OK: ${graceBlocks + 1}개 블록 진행 (${blockBeforeMine} -> ${blockAfterMine}), 캐시된 root 만료`,
  );

  const afterRevoke = await submitTransaction(session);
  assert.equal(
    afterRevoke.status,
    400,
    `구간 B: 폐기된 세션인데 /submitTransaction이 400이 아니다: ${JSON.stringify(afterRevoke.body)}`,
  );
  assert.match(
    String(afterRevoke.body.error),
    /is a member/,
    `구간 B: 오류 메시지가 비멤버십 실패가 아니다: ${JSON.stringify(afterRevoke.body)}`,
  );
  console.log('OK: 구간 B — 지갑이 폐기된 세션의 증명 생성을 거부했다 (400, "is a member")');

  // ===== 구간 C — 체인이 만료된 root를 거부한다 =====
  //
  // calldata#2는 구간 A' 시점의 root로 만들어졌고, 위에서 201블록을 진행시켜 그 root는
  // 이제 GRACE_BLOCKS를 넘겼다. nonce는 1이라 NonceMismatch를 통과하고 isRecentRoot에
  // 도달한다. 여기서 나와야 하는 사유는 반드시 StaleRevocationRoot다 — 그래야 폐기
  // 검사가 실제로 발동했다는 뜻이다. NonceMismatch나 Expired가 나오면 검증하려던 것을
  // 검증하지 못한 것이다.
  let revertName = null;
  try {
    await provider.call({ ...calldata2, from: await signer.getAddress() });
    assert.fail('구간 C: 만료된 root로 보낸 execute()가 revert하지 않았다');
  } catch (err) {
    revertName = decodeRevertName(err);
    if (!revertName) throw err;
  }
  assert.equal(
    revertName,
    'StaleRevocationRoot',
    `구간 C: revert 사유가 StaleRevocationRoot가 아니다 (실제: ${revertName})`,
  );
  console.log('OK: 구간 C — eth_call이 StaleRevocationRoot로 revert했다');

  // eth_call만으로 끝내지 않고 실제 트랜잭션 전송도 거부되는지 확인한다.
  // hardhat 노드는 revert하는 트랜잭션을 status 0으로 채굴하지 않고
  // eth_sendRawTransaction 단계에서 곧바로 오류로 돌려주므로(gasLimit을 명시해
  // estimateGas를 건너뛰어도 마찬가지다), 여기서는 "던져지는 것"이 정상이고
  // 그 오류에 실린 revert 바이트가 StaleRevocationRoot인지를 본다.
  let sendRevertName = null;
  try {
    const staleTx = await signer.sendTransaction({ ...calldata2, gasLimit: 1_000_000 });
    await provider.waitForTransaction(staleTx.hash);
    assert.fail('구간 C: 만료된 root 트랜잭션이 거부되지 않았다');
  } catch (err) {
    sendRevertName = decodeRevertName(err);
    if (!sendRevertName) throw err;
  }
  assert.equal(
    sendRevertName,
    'StaleRevocationRoot',
    `구간 C: 트랜잭션 전송 거부 사유가 StaleRevocationRoot가 아니다 (실제: ${sendRevertName})`,
  );
  console.log('OK: 구간 C — 실제 트랜잭션 전송도 StaleRevocationRoot로 거부됐다');

  // 복구가 실제로 무언가를 되돌리는지 확인한다. 201블록을 진행시켰으므로 이 시점에는
  // 게시된 root가 반드시 만료돼 있어야 한다 — 그렇지 않다면 만료 로직이나 블록
  // 진행이 기대대로 동작하지 않은 것이고, 뒤이은 복구 단언도 의미가 없어진다.
  assert.equal(
    await registry.isRecentRoot(rootToBytes32(await fetchIdpRoot())),
    false,
    '복구 전제가 깨졌다: 블록을 진행시켰는데도 root가 아직 신선하다',
  );
  console.log('OK: 블록 진행으로 게시된 root가 만료된 것을 확인 (복구 대상 존재)');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
