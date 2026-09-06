// Mode 2 폐기(revocation) 전 구간 온체인 E2E 테스트.
//
// 이 테스트가 처음으로 검증하는 것: 살아있는 wallet_agent가 만든 '진짜' pi_pk_i 증명이
// 실제로 배포된 PPIDWallet.execute()를 통과하고(구간 A), 폐기 이후에는 지갑이 스스로
// 증명 생성을 거부하며(구간 B), 새 root가 게시되면 직전 root는 그 즉시 무효가 된다는 것
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
//   - 환경변수 REVOCATION_REGISTRY_ADDRESS: **필수**다(하드코딩 기본값 없음 — 재배포마다
//     낡아 함정이 되므로). 실행 중인 wallet_agent.js가 쓰는 레지스트리 주소를 넘긴다.
//     RevocationRegistry의 운영자 주소는 배포된 컨트랙트의 idp() getter에서 읽는다.
//
// == 이 테스트는 환경을 변경한다 ==
//   - IdP 폐기 트리에 이 실행에서 발급받은 세션의 r_token 리프를 1개 추가한다(되돌릴 수 없음).
//   - RevocationRegistry에 root를 최소 1번 게시한다(대기 중인 폐기 반영).
//   grace window와 K개 순환 버퍼가 없어진 뒤로는 root가 시간이 지나도 만료되지 않으므로,
//   이 테스트는 더 이상 체인 블록을 인위적으로 진행시키지도, 끝에서 별도로 root를
//   복구하지도 않는다 — 구간 B에서 게시하는 root가 그대로 최종 상태이고, 그 상태는
//   fetchIdpRootHex()가 돌려주는 현재 IdP topRoot와 항상 일치한다.
//
// == 멱등성 ==
//   이 테스트는 멱등이 아니지만 재실행은 안전하다. 매 실행마다 새로 로그인해서
//   새 r_token을 발급받으므로, 폐기 대상 리프가 항상 새 값이고 IdP root가 반드시
//   바뀐다(같은 값을 다시 폐기해 root가 안 바뀌는 no-op 상황이 생기지 않는다).
//   누적되는 부작용은 폐기 트리에 리프가 1개씩 쌓이는 것뿐이다.

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

// REVOCATION_REGISTRY_ADDRESS는 필수다. 예전에는 하드코딩 기본값으로 폴백했는데, 그
// 기본값은 재배포(Stage B는 레지스트리를 재배포한다)마다 낡아 실행 중인 wallet_agent.js가
// 실제로 쓰는 배포와 어긋났고, 옛 배포의 isCurrentRoot가 엉뚱하게 revert해 전제조건
// 단계에서 실패하는 함정이 됐다. 낡은 하드코딩을 반복하지 않도록 미설정 시 명확히 실패한다.
const REGISTRY_ADDRESS = process.env.REVOCATION_REGISTRY_ADDRESS;
if (!REGISTRY_ADDRESS) {
  throw new Error(
    'REVOCATION_REGISTRY_ADDRESS is required (no hardcoded default). Pass the registry address the ' +
    'running wallet_agent.js uses:\n' +
    '  REVOCATION_REGISTRY_ADDRESS=0x... IDP_ADMIN_SECRET=... node tests/test_mode2_e2e_onchain.js',
  );
}

// hardhat 기본 니모닉의 0번 계정. 로컬 데모 체인에서 가스비를 낼 자금이 있는 계정으로,
// 브라우저의 MetaMask가 하던 역할(배포/execute 트랜잭션 전송)을 대신한다.
const HARDHAT_ACCOUNT0_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const REGISTRY_ABI = [
  'function idp() view returns (address)',
  'function latestRoot() view returns (bytes32)',
  // v3(이중 트리) 레지스트리는 유예 창이 있어 이름이 다르다. v2의 isCurrentRoot를
  // 그대로 부르면 함수가 없어 정체불명의 revert가 난다.
  'function isAcceptableRoot(bytes32) view returns (bool)',
  // 유예 창 길이. 테스트가 배포 파라미터를 추측하지 않고 체인에서 읽는다.
  'function graceBlocks() view returns (uint256)',
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

  // 동의는 로그인한 브라우저 세션에 묶인다(2026-09-04). 로그인 응답의 세션 쿠키를
  // 들고 다녀야 한다 — request_uri 지식만으로는 동의할 수 없다.
  const loginRes = await fetch(`${IDP}/authorize/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      request_uri: par.request_uri,
      username: 'testuser',
      password: 'password123',
    }),
  });
  const idpSession = (loginRes.headers.get('set-cookie') || '').split(';')[0];
  const login = await loginRes.json();
  if (!login.success) throw new Error(`/authorize/login failed: ${JSON.stringify(login)}`);

  const consent = await (
    await fetch(`${IDP}/authorize/consent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: idpSession },
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

// 게시 대상 root. v3(이중 트리)에서는 두 층의 상위 root를 합친 topRoot이고 **이미
// bytes32**라 필드 원소 변환(rootToBytes32)을 거치면 안 된다. v2 root는 10진 필드
// 원소라 변환이 필요하다 — 그 차이가 이 함수의 반환 형식에 그대로 드러난다.
async function fetchIdpRootHex() {
  const res = await fetch(`${IDP}/idp/revocation_state_v3`);
  if (!res.ok) throw new Error(`/idp/revocation_state_v3 failed: ${res.status}`);
  const { topRoot } = await res.json();
  if (typeof topRoot !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(topRoot)) {
    throw new Error(`revocation_state_v3의 topRoot가 bytes32가 아니다: ${topRoot}`);
  }
  return topRoot;
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

// 대기 중인 폐기를 실제로 게시한다: prepare -> pushRoot -> commit.
// push_revocation_root.cjs는 '이미 게시된 상태'를 다시 올릴 뿐이라 대기 중인 폐기를
// 반영하지 못한다. 배칭 이후 폐기를 유효하게 만드는 경로는 revocation_sweep.cjs
// 하나뿐이므로, 테스트도 운영자와 같은 경로를 쓴다.
function publishPendingRevocations(idpOperatorAddress) {
  return execFileSync(
    'npx',
    ['hardhat', 'run', 'scripts/revocation_sweep.cjs', '--network', 'localhost'],
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

  // pushRoot는 onlyIdP다. 운영자 주소도 하드코딩하지 않고 온체인 getter에서 읽는다.
  const idpOperator = await registry.idp();
  console.log(`OK: registry ${REGISTRY_ADDRESS} idp=${idpOperator}`);

  // 전제조건: 구간 A는 지갑이 'IdP의 현재 root가 이미 온체인에 게시돼 있다'고
  // 가정한다. 그런데 IdP root를 바꾸면서 게시는 하지 않는 다른 테스트
  // (tests/test_idp_revoke_endpoint.js, tests/test_revocation_e2e.js)를 먼저 돌리면
  // 그 가정이 깨져, 구간 A가 검증하려는 것과 무관하게 /submitTransaction이 400으로
  // 실패한다. 자기 전제조건은 스스로 세운다 — 시작 전에 현재 root를 한 번 게시한다.
  if (!(await registry.isAcceptableRoot(await fetchIdpRootHex()))) {
    pushRevocationRoot(idpOperator);
    assert.equal(
      await registry.isAcceptableRoot(await fetchIdpRootHex()),
      true,
      '전제조건 실패: 게시했는데도 IdP의 현재 root가 isCurrentRoot=false다',
    );
    console.log('OK: 전제조건 — IdP의 현재 root가 게시돼 있지 않아 먼저 게시했다');
  }

  // grace window와 K개 순환 버퍼가 없어진 뒤로는 root가 시간이 지나도 만료되지
  // 않는다. 구간 B에서 게시하는 root가 곧 최종 상태이고 fetchIdpRootHex()와 항상
  // 일치하므로, 예전과 달리 별도의 환경 복구가 필요 없다.
  await runSections({ provider, signer, registry, idpOperator, adminSecret });

  console.log(
    'PASS: 폐기 전 구간 온체인 E2E — 진짜 증명이 execute()를 통과하고(A), ' +
      '폐기 후 지갑이 즉시 증명 생성을 거부하며(B), 새 root 게시로 직전 root가 ' +
      '그 즉시 무효가 된다(C)',
  );
}

async function runSections({ provider, signer, registry, idpOperator, adminSecret }) {
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
  //   NonceMismatch -> BadSignature -> UntrustedIdP -> isCurrentRoot -> verifyProof -> Expired
  // 이다. 구간 A의 calldata를 그대로 재전송하면 지갑 nonce 0이 이미 소비돼
  // NonceMismatch가 먼저 걸리고, 폐기 검사(isCurrentRoot)에 도달조차 못 한다.
  // 여기서 미리 받아두는 calldata#2는 nonce 1로 만들어지므로 nonce 검사를 통과해
  // isCurrentRoot까지 도달한다. 이 순서 없이는 구간 C가 검증하려는 것을 검증하지 못한다.
  //
  // calldata#2는 '지금 유효한(= latestRoot인) root'로 만들어진다. 구간 B에서 새
  // root를 게시하면 이 root는 곧바로 직전 root가 되어 구간 C에서 즉시 거부돼야 한다.
  const second = await submitTransaction(session);
  assert.equal(second.status, 200, `구간 A' /submitTransaction 실패: ${JSON.stringify(second.body)}`);
  assert.equal(second.body.deploy, null, "구간 A': 지갑이 이미 배포됐는데 deploy가 null이 아니다");
  const calldata2 = { to: second.body.to, data: second.body.data };
  console.log("OK: 구간 A' — calldata#2 확보 (nonce 1, 지금 유효한 root, 전송하지 않음)");

  // ===== 구간 B — 지갑이 폐기된 크레덴셜로 증명 생성을 거부한다 =====
  const rootBeforeRevoke = await fetchIdpRootHex();
  const revokeRes = await fetch(`${IDP}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': adminSecret },
    body: JSON.stringify({ type: 'session', value: session.statement.r_token }),
  });
  const revokeBody = await revokeRes.json();
  assert.equal(revokeRes.status, 200, `/idp/revoke 실패: ${JSON.stringify(revokeBody)}`);
  assert.equal(revokeBody.pending, true, '/idp/revoke가 폐기를 대기열에 넣지 않았다');
  console.log('OK: IdP가 이 세션의 r_token 폐기를 접수했다 (대기열)');

  // 배칭의 핵심 성질: 게시 전까지 IdP가 서빙하는 상태는 조금도 변하지 않는다.
  // 예전에는 폐기 즉시 IdP root가 바뀌는데 온체인 root는 그대로라, 그 사이에 지갑이
  // 만든 witness의 root가 게시돼 있지 않아 '폐기와 무관한 정상 사용자 전원'의
  // /submitTransaction이 400으로 막혔다. 그 장애 창이 없어졌는지를 여기서 단언한다.
  assert.equal(
    await fetchIdpRootHex(),
    rootBeforeRevoke,
    '배칭 위반: 폐기 접수만으로 게시된 IdP root가 바뀌었다',
  );
  const beforePublish = await submitTransaction(session);
  assert.equal(
    beforePublish.status,
    200,
    `배칭 위반: 게시 전인데 /submitTransaction이 200이 아니다: ${JSON.stringify(beforePublish.body)}`,
  );
  console.log('OK: 폐기 접수 직후 — 게시 전까지 IdP root 불변, 트랜잭션도 계속 동작한다 (배칭)');

  // 이제 실제로 게시한다: prepare -> pushRoot -> commit. grace window가 없으므로
  // latestRoot가 바뀌는 이 순간, 캐시된 pi_pk_i 증명(폐기 전 root 기준)은 그 즉시
  // 더 이상 '현재 root'가 아니게 된다 — grace 시절처럼 "폐기 직후에도 한동안은
  // 캐시가 통해 200이 나오는" 시간 창이 이제는 없다.
  publishPendingRevocations(idpOperator);
  const publishedRoot = await fetchIdpRootHex();
  assert.notEqual(publishedRoot, rootBeforeRevoke, '게시했는데도 IdP root가 그대로다');
  assert.equal(
    await registry.isAcceptableRoot(publishedRoot),
    true,
    '게시 후 새 root가 레지스트리에 등록되지 않았다',
  );
  console.log('OK: 대기 중이던 폐기를 게시했다 (IdP root 전진 + 온체인 latestRoot 갱신 확인)');

  // v3에서는 폐기가 **유예 창(graceBlocks)만큼 뒤에** 효력을 갖는다. 그 창 동안은
  // 직전 root가 여전히 isAcceptableRoot이므로, 지갑은 캐시된 증명을 그대로 쓰고
  // 트랜잭션도 통과한다 — 인플라이트 보호의 대가이고 설계 문서 6절에 적힌 교환이다.
  // (v2에는 grace가 없어 게시 즉시 막혔다. 그 차이가 여기서 드러난다.)
  const stillInGrace = await submitTransaction(session);
  assert.equal(
    stillInGrace.status,
    200,
    `구간 B: 유예 창 안에서는 아직 통과해야 한다: ${JSON.stringify(stillInGrace.body)}`,
  );
  console.log('OK: 구간 B — 유예 창 안에서는 폐기가 아직 효력을 갖지 않는다 (설계상 K블록 지연)');

  // 창을 넘긴다. graceBlocks는 레지스트리에서 직접 읽어 테스트가 배포 파라미터를
  // 추측하지 않게 한다.
  const graceBlocks = Number(await registry.graceBlocks());
  for (let i = 0; i < graceBlocks + 1; i++) {
    await provider.send('evm_mine', []);
  }
  // 이제 직전 root가 창 밖이라 지갑은 IdP 재조회 경로를 타고, 이 세션의 r_token이
  // 이미 폐기된 리프임을 발견해 비멤버십 witness를 만들지 못하고 스스로 멈춘다.
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
  console.log(
    `OK: 구간 B — 유예 창(${graceBlocks}블록)이 지나자 지갑이 폐기된 세션의 증명 생성을 거부했다 (400, "is a member")`,
  );

  // ===== 구간 C — 새 root가 게시되면 직전 root는 그 즉시 무효가 된다 =====
  //
  // calldata#2는 구간 A'에서 만들어졌고, 그 시점의 root는 rootBeforeRevoke
  // (=구간 B가 교체한 직전 root)다. 구간 B에서 유예 창을 이미 넘겼으므로 이건
  // "아직 유효한 최근 root"가 아니라 창 밖으로 밀려난 틀린 root다.
  // nonce는 1이라 NonceMismatch를 통과하고 root 검사(isAcceptableRoot)에서 막혀야 한다.
  // 여기서 나와야 하는 사유는 반드시 StaleRevocationRoot다 — 그래야 폐기 검사가
  // 실제로 발동했다는 뜻이다. NonceMismatch나 Expired가 나오면 검증하려던 것을
  // 검증하지 못한 것이다.
  let revertName = null;
  try {
    await provider.call({ ...calldata2, from: await signer.getAddress() });
    assert.fail('구간 C: 직전 root로 보낸 execute()가 revert하지 않았다');
  } catch (err) {
    revertName = decodeRevertName(err);
    if (!revertName) throw err;
  }
  assert.equal(
    revertName,
    'StaleRevocationRoot',
    `구간 C: revert 사유가 StaleRevocationRoot가 아니다 (실제: ${revertName})`,
  );
  console.log('OK: 구간 C — eth_call이 직전 root를 즉시 StaleRevocationRoot로 거부했다 (창 없음)');

  // eth_call만으로 끝내지 않고 실제 트랜잭션 전송도 거부되는지 확인한다.
  // hardhat 노드는 revert하는 트랜잭션을 status 0으로 채굴하지 않고
  // eth_sendRawTransaction 단계에서 곧바로 오류로 돌려주므로(gasLimit을 명시해
  // estimateGas를 건너뛰어도 마찬가지다), 여기서는 "던져지는 것"이 정상이고
  // 그 오류에 실린 revert 바이트가 StaleRevocationRoot인지를 본다.
  let sendRevertName = null;
  try {
    const staleTx = await signer.sendTransaction({ ...calldata2, gasLimit: 1_000_000 });
    await provider.waitForTransaction(staleTx.hash);
    assert.fail('구간 C: 직전 root 트랜잭션이 거부되지 않았다');
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

  // grace 시절에는 여기서 체인을 만료 지점까지 진행시켰으므로 게시된 root도 함께
  // 만료돼 별도 복구가 필요했다. 이제는 구간 C가 실패하는(revert하는) 트랜잭션만
  // 보냈을 뿐 latestRoot를 바꾸지 않았으므로, 환경은 구간 B가 게시한 상태 그대로
  // 여전히 일관적이다 — 복구할 것이 없다는 사실 자체를 여기서 확인한다.
  assert.equal(
    await registry.isAcceptableRoot(await fetchIdpRootHex()),
    true,
    '환경 불변 위반: 구간 C 이후 latestRoot가 현재 IdP root와 어긋났다',
  );
  console.log('OK: 구간 C 이후에도 latestRoot === 현재 IdP root (복구 불필요)');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
