# RP FE(client.js) + server.js Statement 검증 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `client.js`가 wallet_agent.js의 새 loopback+OIDC 로그인 흐름(`/startLogin`+`/loginStatus` 폴링+Snap `confirmLogin`)을 사용해 로그인을 완주하고, `server.js`가 새 9-field PairCT statement를 독립 검증해서 RP 세션을 수립하며, 이제 안 쓰는 팝업/relay 코드가 제거된 상태로 만든다.

**Architecture:** `custom_idp.js`의 `/token`이 새 9-field statement와 함께 옛 6-field `IDP_TOKEN` 서명(`idpToken`)도 병행 발급하고(회로/온체인 컨트랙트는 안 건드림), `wallet_agent.js`가 그 값을 job 결과로 포워딩한다. `client.js`는 job 폴링으로 로그인을 진행하고, 완료된 statement를 새 `server.js` 엔드포인트(`/api/mode2/verify_statement`)로 검증받아 세션을 수립한 뒤, 포워딩된 `idpToken`으로 기존 온체인 tx 제출(`/submitTransaction`)을 계속 사용한다.

**Tech Stack:** Express(`custom_idp.js`/`server.js`/`wallet_agent.js`), circomlibjs(EdDSA-Poseidon), 바닐라 브라우저 JS(`client.js`), MetaMask Snap.

## Global Constraints

- 서명 도메인 분리자: `DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT')`(9-field: `[DOMAIN, iss, aud, nonce, arid_i, auid_i, r_token, max_height, chain_id]`)와 `DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN')`(6-field: `[DOMAIN, arid_i, auid_i, r_token, max_height, chain_id]`)는 서로 다른 목적(새 statement=RP 세션 수립 / 옛 idpToken=온체인 tx 제출)이며 절대 섞어 쓰지 않는다.
- `iss` 상수값은 `'custom-idp'`, `aud`/`client_id` 상수값은 `'pairct-wallet'` — 모든 파일에서 동일한 리터럴을 그대로 하드코딩한다(공유 상수 모듈을 새로 만들지 않는다. 기존 코드도 각 파일에 리터럴로 중복돼 있다).
- `statement.exp`는 서명 메시지(9-field)에 포함되지 않는 비서명 필드다. 어떤 검증 로직에서도 만료 판단에 쓰지 않는다 — `max_height`만 권위 있는 만료 기준이다.
- `server.js`의 세션 쿠키 이름은 `rp_sid`(express-session, `server.js:330-336`)다.
- `client.js`의 `/loginStatus` 폴링 간격은 1000ms(`POLL_INTERVAL_MS`)로 고정한다.
- 다음 파일/컨트랙트는 이번 계획에서 수정하지 않는다: `circuits/pi_pk_i.circom`, 이미 배포된 `PiPkIVerifier`/`PPIDWalletFactory` 컨트랙트, `custom_idp.js`의 `/register_rp`·`/sso_with_credentials`·`/consent_result`·`GET /login_popup` 라우트, `wallet_agent.js`의 `GET /relay` 라우트·`/wallet` 정적 서빙·`POST /verifyIdPAuthToken` 엔드포인트.
- 새로 추가하는 코드 주석은 이 저장소의 기존 관례를 따라 한글로, "왜"가 비자명한 경우에만 작성한다.
- 각 태스크는 해당 태스크가 손댄 파일만 `git add`해서 커밋한다(무관한 변경 스테이징 금지).

---

### Task 1: custom_idp.js — `/token` 응답에 옛 포맷 `idpToken` 병행 발급

**Files:**
- Modify: `custom_idp.js:404-479` (`/token` 핸들러)
- Test: Create `tests/test_token_legacy_idptoken.js`

**Interfaces:**
- Consumes: 없음(이 태스크는 최초 태스크).
- Produces: `/token` JSON 응답에 새 최상위 필드 `idpToken: { arid_i, auid_i, r_token, max_height, chain_id, signature: { R8: [string, string], S: string } }` 추가. `arid_i`/`auid_i`/`r_token`/`max_height`/`chain_id` 값은 기존 `statement`의 동일 이름 필드와 항상 같은 값(같은 `record`에서 나옴). Task 2가 이 `idpToken` 필드를 소비한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_token_legacy_idptoken.js` 파일을 새로 만든다:

```javascript
// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running. Run: node tests/test_token_legacy_idptoken.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';
import { createHash, randomBytes } from 'crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  const res = await fetch(`${SERVER}/api/mode2/wallet_agent_token`);
  if (!res.ok) throw new Error(`wallet_agent_token failed: ${res.status}`);
  return (await res.json()).token;
}

async function registerAndGenerateProof() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  })).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);
  return step8;
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const addressBytes = keccak256('0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex')).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]));
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature = '0x' + sigRaw.r.toString(16).padStart(64, '0') + sigRaw.s.toString(16).padStart(64, '0') + (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function getCode(codeChallenge, redirectUri) {
  const step8 = await registerAndGenerateProof();
  const state = 'legacy-idptoken-test-state';
  const nonce = 'legacy-idptoken-test-nonce';
  const requestBinding = signBinding(state, nonce, codeChallenge);
  const par = await (await fetch(`${IDP}/par`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: redirectUri, response_type: 'code',
      state, nonce, code_challenge: codeChallenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, chain_id: step8.chain_id,
      requestBinding,
    }),
  })).json();
  await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, username: 'testuser', password: 'password123' }),
  });
  const consent = await (await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, allowed: true }),
  })).json();
  return new URL(consent.redirectTo).searchParams.get('code');
}

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function valueToField(value) {
  const str = String(value);
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

async function main() {
  const redirectUri = 'http://127.0.0.1:49997/oidc/callback';
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  console.log('-- /token also returns a legacy 6-field idpToken alongside the new statement --');
  const code = await getCode(codeChallenge, redirectUri);
  const tokenRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  });
  const statement = await tokenRes.json();
  if (tokenRes.status !== 200 || !statement.signature) {
    throw new Error(`FAIL: expected 200 + signature, got ${tokenRes.status} ${JSON.stringify(statement)}`);
  }
  if (!statement.idpToken || !statement.idpToken.signature) {
    throw new Error(`FAIL: expected statement.idpToken.signature, got ${JSON.stringify(statement.idpToken)}`);
  }
  if (
    statement.idpToken.arid_i !== statement.arid_i ||
    statement.idpToken.auid_i !== statement.auid_i ||
    statement.idpToken.r_token !== statement.r_token ||
    statement.idpToken.max_height !== statement.max_height ||
    statement.idpToken.chain_id !== statement.chain_id
  ) {
    throw new Error(`FAIL: statement.idpToken fields do not match statement fields: ${JSON.stringify(statement)}`);
  }
  console.log('PASS: statement.idpToken carries the same arid_i/auid_i/r_token/max_height/chain_id as statement');

  console.log('-- statement.idpToken.signature verifies against the 6-field IDP_TOKEN domain (not PAIRCT_STATEMENT) --');
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const idpKeysRes = await (await fetch(`${IDP}/ps_public_keys`)).json();
  const pkIdP = [eddsa.F.e(BigInt(idpKeysRes.pk_IdP[0])), eddsa.F.e(BigInt(idpKeysRes.pk_IdP[1]))];

  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msg = poseidon([
    DOMAIN_IDP_TOKEN,
    valueToField(statement.idpToken.arid_i),
    valueToField(statement.idpToken.auid_i),
    valueToField(statement.idpToken.r_token),
    valueToField(statement.idpToken.max_height),
    valueToField(statement.idpToken.chain_id),
  ]);
  const sigForVerify = {
    R8: [eddsa.F.e(BigInt(statement.idpToken.signature.R8[0])), eddsa.F.e(BigInt(statement.idpToken.signature.R8[1]))],
    S: BigInt(statement.idpToken.signature.S),
  };
  if (!eddsa.verifyPoseidon(msg, sigForVerify, pkIdP)) {
    throw new Error('FAIL: statement.idpToken.signature does not verify against the 6-field IDP_TOKEN message');
  }
  console.log('PASS: statement.idpToken.signature verifies against the legacy 6-field IDP_TOKEN domain');

  console.log('ALL LEGACY IDPTOKEN TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: 서버 3개(custom_idp.js:4000, server.js:3000, wallet_agent.js:5001) 실행 후 테스트를 돌려서 실패를 확인**

Run: `node tests/test_token_legacy_idptoken.js`
Expected: `FAIL: expected statement.idpToken.signature, got undefined`로 실패 (아직 `idpToken` 필드가 없으므로).

- [ ] **Step 3: `custom_idp.js`의 `/token` 핸들러에 `idpToken` 발급 추가**

`custom_idp.js:441-478`(기존 `const exp = ...`부터 `res.json({...})` 끝까지)을 아래로 교체한다:

```javascript
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT');
  const msgFields = [
    DOMAIN_PAIRCT_STATEMENT,
    valueToField('custom-idp'),
    valueToField(PAIRCT_CLIENT_ID),
    valueToField(record.nonce),
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ];
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);

  // 온체인 tx 제출(wallet_agent.js의 /submitTransaction, pi_pk_i 회로)은 이미 배포된
  // PiPkIVerifier가 옛 6-field IDP_TOKEN 도메인 서명만 검증하도록 불변으로 고정돼
  // 있다. 회로/컨트랙트를 바꾸는 대신, 같은 값들로 그 옛 포맷 서명도 하나 더
  // 만들어서 새 statement와 함께 내려준다 — 둘은 서로 다른 도메인 분리자를 쓰는
  // 별개 서명이라 절대 섞어 쓸 수 없다.
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const idpTokenMsg = poseidon([
    DOMAIN_IDP_TOKEN,
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ]);
  const idpTokenSig = eddsa.signPoseidon(idpEdDSAKeys.prv, idpTokenMsg);

  // B2 authorized-opening trace logs — same bookkeeping the old
  // verifyPiIAndIssueToken does, so statements issued via this new flow stay
  // traceable through the existing /idp/lookup_uid_by_r_token and
  // /idp/lookup_uid_by_auid_i endpoints.
  issuanceLog.set(String(record.token_nonce), record.uid);
  auidILog.set(String(record.auid_i), record.uid);

  res.json({
    iss: 'custom-idp',
    aud: PAIRCT_CLIENT_ID,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    r_token: record.token_nonce,
    max_height: record.max_height,
    chain_id: record.chain_id,
    exp,
    signature: {
      R8: [eddsa.F.toObject(sig.R8[0]).toString(), eddsa.F.toObject(sig.R8[1]).toString()],
      S: sig.S.toString(),
    },
    idpToken: {
      arid_i: record.arid_i,
      auid_i: record.auid_i,
      r_token: record.token_nonce,
      max_height: record.max_height,
      chain_id: record.chain_id,
      signature: {
        R8: [eddsa.F.toObject(idpTokenSig.R8[0]).toString(), eddsa.F.toObject(idpTokenSig.R8[1]).toString()],
        S: idpTokenSig.S.toString(),
      },
    },
  });
});
```

주의: 기존 코드에 이미 있던 `issuanceLog.set(...)`/`auidILog.set(...)` 두 줄(원래 `authorizationCodes.delete(code)` 직후, `res.json` 직전)의 위치는 그대로 유지한다 — 위 교체 블록에 이미 포함돼 있으므로 중복 추가하지 않는다.

- [ ] **Step 4: custom_idp.js를 재시작하고 테스트가 통과하는지 확인**

`custom_idp.js` 재시작이 필요하다 — CLAUDE.md 규칙대로 재시작 전 사용자에게 먼저 확인하고, 재시작 시 PS/EdDSA 키가 새로 생성되므로 `server.js` 재시작 → `scripts/redeploy_ppid_factory.cjs` → 새 factory 주소로 `wallet_agent.js` 재시작까지 체인으로 이어서 진행한다.

Run: `node tests/test_token_legacy_idptoken.js`
Expected: `ALL LEGACY IDPTOKEN TESTS PASSED`

기존 `tests/test_token_endpoint.js`, `tests/test_par_authorize_token_e2e.js`도 회귀 확인을 위해 같이 돌린다(둘 다 새 `idpToken` 필드를 모르고 무시하므로 그대로 통과해야 한다).

Run: `node tests/test_token_endpoint.js && node tests/test_par_authorize_token_e2e.js`
Expected: 둘 다 `ALL ... TESTS PASSED`

- [ ] **Step 5: 커밋**

```bash
git add custom_idp.js tests/test_token_legacy_idptoken.js
git commit -m "feat(mode2): /token also issues legacy 6-field idpToken for on-chain tx compat"
```

---

### Task 2: wallet_agent.js — `job.result`에 `idpToken` 포워딩

**Files:**
- Modify: `wallet_agent.js:773-784` (`exchangeToken` 함수의 `job.result` 조립부)

**Interfaces:**
- Consumes: Task 1이 추가한 `/token` 응답의 `idpToken` 필드.
- Produces: `GET /loginStatus`의 `done` 응답에 최상위 필드 `idpToken`(Task 1의 것과 동일 shape) 추가. `statement` 필드에는 더 이상 `idpToken`이 중첩되지 않는다(분리됨). Task 4(`client.js`)가 `data.idpToken`, `data.statement` 둘 다 소비한다.

- [ ] **Step 1: `exchangeToken`의 `job.result` 조립 수정**

`wallet_agent.js:773-784`를 아래로 교체한다:

```javascript
async function exchangeToken(jobId, code, redirectUri, codeVerifier) {
  const job = loginJobs.get(jobId);
  if (!job) return;

  const tokenRes = await fetch(`${IDP_ORIGIN}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: 'pairct-wallet',
      code_verifier: codeVerifier,
    }),
  });
  const statement = await tokenRes.json();
  if (!tokenRes.ok || !statement.signature) {
    throw new Error(statement.error_description || statement.error || '/token failed');
  }

  const step8 = job.step8;
  // /token 응답에는 새 9-field statement 필드와 옛 6-field idpToken(온체인 tx
  // 제출 전용, /submitTransaction이 소비)이 함께 실려 온다. statement 전체를
  // 그대로 job.result.statement에 복사하면 idpToken이 그 안에 중첩되어 남으므로,
  // 구조 분해로 분리해서 둘을 독립된 필드로 둔다.
  const { idpToken, ...statementFields } = statement;
  job.status = 'done';
  job.result = {
    ppid: step8.ppid,
    arid_i: step8.arid_i,
    auid_i: step8.auid_i,
    pk_i: step8.pk_i,
    publicKeyHex: step8.publicKeyHex,
    pi_PPID: step8.pi_PPID,
    statement: statementFields,
    idpToken,
  };
  console.log(`[WalletAgent][loopback] job ${jobId} done`);
```

`console.log` 다음 줄(함수 닫는 `}`)은 그대로 둔다.

- [ ] **Step 2: 기존 loopback 테스트로 회귀 확인**

wallet_agent.js를 재시작한다(이 태스크는 `custom_idp.js` 키를 건드리지 않으므로 단독 재시작으로 충분하다).

Run: `node tests/test_wallet_login_loopback.js`
Expected: `ALL WALLET LOOPBACK TESTS PASSED (manual browser completion not covered — see design spec)` — 이 테스트는 `awaiting_browser_login`까지만 확인하므로(설계 문서 §참고, 파일 상단 주석 참고) 이번 변경(콜백 이후 로직)은 자동 검증 범위 밖이다. 아래 Step 3에서 수동으로 확인한다.

- [ ] **Step 3: 수동 검증 — 실제 브라우저로 loopback 완주 후 `job.result.idpToken` 확인**

`index.html`을 브라우저로 열고(MetaMask + Snap 연결된 상태) "Delegated Login" 버튼을 눌러 실제 로그인을 한 번 완주한다(Task 4가 아직 없으므로 이 단계에서는 client.js가 여전히 옛 흐름을 쓸 수 있다 — 대신 curl/브라우저 개발자 도구로 직접 `/startLogin`→`/confirmLoginResult`→시스템 브라우저 로그인까지 수동으로 진행해 `jobId`를 얻는다). `jobId`를 얻은 뒤:

Run: `curl "http://127.0.0.1:5001/loginStatus?jobId=<jobId>"`
Expected: `status: "done"` 응답에 최상위 `idpToken.signature.{R8,S}`가 있고, `statement` 객체 안에는 `idpToken` 키가 없는지 확인(`echo '<응답 JSON>' | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log('idpToken top-level:', !!d.idpToken); console.log('idpToken nested in statement:', !!d.statement?.idpToken);"` 같은 방식으로 확인 가능).

- [ ] **Step 4: 커밋**

```bash
git add wallet_agent.js
git commit -m "feat(mode2): forward legacy idpToken from /token into login job result"
```

---

### Task 3: server.js — `POST /api/mode2/verify_statement`

**Files:**
- Modify: `server.js` (새 라우트를 `/api/mode2/sso_success` 핸들러 바로 뒤, `server.js:747`의 `});` 다음 줄에 추가)
- Test: Create `tests/test_verify_statement_endpoint.js`

**Interfaces:**
- Consumes: Task 1이 만드는 `/token`의 9-field statement 응답 형태(`{iss,aud,nonce,arid_i,auid_i,r_token,max_height,chain_id,exp,signature:{R8,S}}`). `server.js`에 이미 있는 `assertCanonicalField`, `FIELD_PRIME`, `valueToField`, `poseidon`, `eddsa`, `ensureEdDSA`, `rawIdpPublicKeys`, `idpPublicKeys`, `psParams`, `initRP_PS`, `getRpcChainId`, `getCurrentHeightForToken`, `computeWalletAddress`, `walletAddressToAuidI`, `rpRegistration`(모두 기존 `/api/mode2/sso_success` 핸들러가 이미 쓰는 것과 동일한 모듈 스코프 바인딩).
- Produces: `POST /api/mode2/verify_statement` — 요청 `{statement, ppid}`, 성공 시 `{success:true}`(200), 실패 시 `{success:false, error}`(400/401/403/500/503). Task 4(`client.js`)가 이 엔드포인트를 호출한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_verify_statement_endpoint.js` 파일을 새로 만든다:

```javascript
// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running and key-consistent. Run: node tests/test_verify_statement_endpoint.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';
import { createHash, randomBytes } from 'crypto';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

function extractSessionCookie(res) {
  const raw = res.headers.get('set-cookie');
  if (!raw) throw new Error('no set-cookie header returned');
  return raw.split(';')[0]; // "rp_sid=..."
}

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function startRpSession() {
  const nonceRes = await fetch(`${SERVER}/api/mode2/rp_credential_nonce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionNonce: '0xaaaa' }),
  });
  const cookie = extractSessionCookie(nonceRes);
  const body = await nonceRes.json();
  return { cookie, rpCredential: body.rpCredential, rpNonce: body.rpNonce };
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const addressBytes = keccak256('0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex')).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]));
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature = '0x' + sigRaw.r.toString(16).padStart(64, '0') + sigRaw.s.toString(16).padStart(64, '0') + (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function getStatement(rpCredential, rpNonce, redirectUri) {
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential, r_i: '0xaaaa', rpNonce }),
  })).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);

  const state = `verify-statement-test-state-${Date.now()}-${Math.random()}`;
  const nonce = `verify-statement-test-nonce-${Date.now()}-${Math.random()}`;
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const requestBinding = signBinding(state, nonce, codeChallenge);

  const par = await (await fetch(`${IDP}/par`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: redirectUri, response_type: 'code',
      state, nonce, code_challenge: codeChallenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, chain_id: step8.chain_id,
      requestBinding,
    }),
  })).json();
  await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, username: 'testuser', password: 'password123' }),
  });
  const consent = await (await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, allowed: true }),
  })).json();
  const code = new URL(consent.redirectTo).searchParams.get('code');

  const tokenRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  });
  const statement = await tokenRes.json();
  if (tokenRes.status !== 200 || !statement.signature) {
    throw new Error(`FAIL: could not obtain statement: ${tokenRes.status} ${JSON.stringify(statement)}`);
  }
  return { statement, ppid: step8.ppid };
}

async function main() {
  console.log('-- happy path: valid statement + matching RP session is accepted --');
  const session = await startRpSession();
  const { statement, ppid } = await getStatement(session.rpCredential, session.rpNonce, 'http://127.0.0.1:49995/oidc/callback');
  const okRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session.cookie },
    body: JSON.stringify({ statement, ppid }),
  });
  const okBody = await okRes.json();
  if (!okRes.ok || !okBody.success) throw new Error(`FAIL: expected success, got ${okRes.status} ${JSON.stringify(okBody)}`);
  console.log('PASS: valid statement accepted, RP session established');

  console.log('-- tampered iss is rejected --');
  const session2 = await startRpSession();
  const { statement: statement2, ppid: ppid2 } = await getStatement(session2.rpCredential, session2.rpNonce, 'http://127.0.0.1:49994/oidc/callback');
  const tamperedIss = { ...statement2, iss: 'evil-idp' };
  const issRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session2.cookie },
    body: JSON.stringify({ statement: tamperedIss, ppid: ppid2 }),
  });
  if (issRes.ok) throw new Error('FAIL: tampered iss was accepted');
  console.log('PASS: tampered iss rejected');

  console.log('-- statement issued for a different RP session (arid_i mismatch) is rejected --');
  const session3 = await startRpSession();
  const { statement: statement3, ppid: ppid3 } = await getStatement(session3.rpCredential, session3.rpNonce, 'http://127.0.0.1:49993/oidc/callback');
  const session4 = await startRpSession(); // 다른 rpNonce를 발급받은 별개 세션
  const wrongAudRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session4.cookie },
    body: JSON.stringify({ statement: statement3, ppid: ppid3 }),
  });
  if (wrongAudRes.status !== 403) throw new Error(`FAIL: expected 403 on arid_i mismatch, got ${wrongAudRes.status}`);
  console.log('PASS: cross-session replay rejected (arid_i audience check)');

  console.log('-- tampered signature is rejected --');
  const session5 = await startRpSession();
  const { statement: statement5, ppid: ppid5 } = await getStatement(session5.rpCredential, session5.rpNonce, 'http://127.0.0.1:49992/oidc/callback');
  const tamperedSig = { ...statement5, signature: { ...statement5.signature, S: statement5.signature.S + '1' } };
  const sigRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session5.cookie },
    body: JSON.stringify({ statement: tamperedSig, ppid: ppid5 }),
  });
  if (sigRes.ok) throw new Error('FAIL: tampered signature was accepted');
  console.log('PASS: tampered signature rejected');

  console.log('ALL VERIFY_STATEMENT TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: 테스트를 돌려서 실패를 확인**

Run: `node tests/test_verify_statement_endpoint.js`
Expected: 첫 번째 케이스(`happy path`)에서 `FAIL: expected success, got 404 ...`로 실패(엔드포인트가 아직 없으므로).

- [ ] **Step 3: `server.js`에 `/api/mode2/verify_statement` 추가**

`server.js:747`의 `});`(=== `/api/mode2/sso_success` 핸들러의 끝) 바로 다음 줄에 아래 라우트를 삽입한다:

```javascript

// Mode 2: 새 PairCT signed login statement(9-field, loopback+OIDC 흐름) 검증.
// 기존 /api/mode2/sso_success(옛 6-field idpToken)는 그대로 두고 병행 추가한다.
app.post('/api/mode2/verify_statement', async (req, res) => {
  const { statement, ppid } = req.body;

  if (!statement) {
    return res.status(400).json({ success: false, error: 'Missing statement for RP verification' });
  }
  if (!ppid) {
    return res.status(400).json({ success: false, error: 'Missing ppid for RP verification' });
  }

  console.log('--- [RP Backend] Verifying PairCT login statement + RP Audience ---');

  try {
    assertCanonicalField(statement.arid_i, 'statement.arid_i');
    assertCanonicalField(statement.auid_i, 'statement.auid_i');
    assertCanonicalField(statement.r_token, 'statement.r_token');
    assertCanonicalField(statement.max_height, 'statement.max_height');
    assertCanonicalField(statement.chain_id, 'statement.chain_id');
    if (!Array.isArray(statement.signature?.R8) || statement.signature.R8.length !== 2 || !statement.signature?.S) {
      throw new Error('statement.signature is missing or malformed');
    }
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  if (statement.iss !== 'custom-idp') {
    return res.status(400).json({ success: false, error: 'Unexpected statement.iss' });
  }
  if (statement.aud !== 'pairct-wallet') {
    return res.status(400).json({ success: false, error: 'Unexpected statement.aud' });
  }

  // 0. RP 본인의 rid와 rp_nonce로 arid_i를 직접 재계산해서 검증 (Audience Check).
  // IdP는 rid를 모르므로 이 확인은 전적으로 RP 자신의 책임이다.
  if (!rpRegistration || !rpRegistration.rid) {
    return res.status(500).json({ success: false, error: 'RP is not properly registered yet' });
  }
  const sessionRpNonce = req.session.rpNonce;
  if (!sessionRpNonce) {
    return res.status(400).json({ success: false, error: 'No rp_nonce has been issued for this session yet' });
  }

  await ensureEdDSA();
  if (!idpPublicKeys || !psParams.g2) {
    console.log('[Mode 2] IdP public keys not loaded yet. Retrying before statement verification...');
    await initRP_PS();
  }

  const expectedAridI = (valueToField(rpRegistration.rid) * valueToField(sessionRpNonce)) % FIELD_PRIME;
  if (String(statement.arid_i) !== String(expectedAridI)) {
    console.error(`❌ [RP Backend] Audience Check FAILED! statement.arid_i does not match this RP's rid * rp_nonce.`);
    return res.status(403).json({ success: false, error: 'Security Alert: Wrong RP Identity (arid_i mismatch). Potential cross-service replay attack.' });
  }

  console.log('✅ [RP Backend] Audience Check PASSED (statement.arid_i matches this RP\'s rid * rp_nonce).');

  try {
    const maxHeight = BigInt(statement.max_height);
    const currentHeight = await getCurrentHeightForToken();
    const rpcChainId = await getRpcChainId();
    if (String(statement.chain_id) !== rpcChainId) {
      console.error('[RP Backend] chain_id check FAILED:', {
        statement_chain_id: statement.chain_id,
        rpc_chain_id: rpcChainId,
        source: currentHeight.source,
      });
      return res.status(401).json({ success: false, error: 'Statement chain_id does not match RP verification chain' });
    }
    console.log('[RP Backend] chain_id check PASSED:', {
      chain_id: rpcChainId,
      source: currentHeight.source,
    });
    if (currentHeight.value > maxHeight) {
      console.error('[RP Backend] max_height check FAILED:', {
        current: currentHeight.value.toString(),
        max_height: maxHeight.toString(),
        source: currentHeight.source,
      });
      return res.status(401).json({ success: false, error: 'Statement expired by max_height' });
    }
    console.log('[RP Backend] max_height check PASSED:', {
      current: currentHeight.value.toString(),
      max_height: maxHeight.toString(),
      source: currentHeight.source,
    });
  } catch (err) {
    console.error('[RP Backend] max_height verification error:', err.message);
    return res.status(503).json({ success: false, error: `Unable to verify max_height: ${err.message}` });
  }

  // EdDSA-Poseidon 검증 — custom_idp.js의 /token이 서명한 것과 동일하게 9개 필드를
  // Poseidon으로 묶어서 msg를 재계산한 뒤, IdP의 pk_IdP로 검증한다. 옛 idpToken의
  // DOMAIN_IDP_TOKEN(6-field)과는 다른 도메인 분리자라 절대 서로 바꿔 쓸 수 없다.
  const DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT');
  const msgFields = [
    DOMAIN_PAIRCT_STATEMENT,
    valueToField('custom-idp'),
    valueToField('pairct-wallet'),
    valueToField(statement.nonce),
    valueToField(statement.arid_i),
    valueToField(statement.auid_i),
    valueToField(statement.r_token),
    valueToField(statement.max_height),
    valueToField(statement.chain_id),
  ];
  const msg = poseidon(msgFields);

  const pkIdPRaw = rawIdpPublicKeys?.pk_IdP;
  if (!pkIdPRaw || pkIdPRaw.length !== 2) {
    return res.status(503).json({ success: false, error: 'IdP EdDSA public key not loaded yet' });
  }
  let isSigValid;
  try {
    const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
    const sigForVerify = {
      R8: [eddsa.F.e(BigInt(statement.signature.R8[0])), eddsa.F.e(BigInt(statement.signature.R8[1]))],
      S: BigInt(statement.signature.S),
    };
    isSigValid = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);
  } catch (err) {
    return res.status(400).json({ success: false, error: 'Malformed EdDSA-Poseidon signature data' });
  }

  if (!isSigValid) {
    return res.status(401).json({ success: false, error: 'Invalid EdDSA-Poseidon Signature' });
  }

  // B2 추적용: 기존 sso_success와 동일한 방식으로 ppid -> auid_i를 기록한다.
  try {
    const walletAddress = await computeWalletAddress(ppid);
    walletAddressToAuidI.set(walletAddress.toLowerCase(), statement.auid_i);
  } catch (err) {
    console.error(`[RP Backend] Failed to record ppid->auid_i for B2 trace: ${err.message}`);
  }

  delete req.session.rpNonce;

  console.log('[Mode 2] Statement verification SUCCESS. Session established.');
  res.json({ success: true });
});
```

- [ ] **Step 4: server.js 재시작 후 테스트 통과 확인**

Run: `node tests/test_verify_statement_endpoint.js`
Expected: `ALL VERIFY_STATEMENT TESTS PASSED`

기존 `tests/test_mode2_integration.js`는 이미 낡은(mock proof 기반) 테스트라 이번 변경과 무관하게 실패할 수 있다 — 이번 태스크가 원인인지 확인하려면 이 변경 전에도 실패했는지 `git stash`로 비교하거나, 실패 메시지가 `/api/mode2/sso_success`(옛 엔드포인트, 안 건드림) 관련인지만 확인한다.

- [ ] **Step 5: 커밋**

```bash
git add server.js tests/test_verify_statement_endpoint.js
git commit -m "feat(mode2): add /api/mode2/verify_statement for the 9-field PairCT statement"
```

---

### Task 4: client.js — 새 로그인 흐름 배선 + `submitPPIDTransaction` 재배선 + 옛 코드 제거

**Files:**
- Modify: `client.js`

**Interfaces:**
- Consumes: Task 3의 `POST /api/mode2/verify_statement`(`{statement, ppid}` → `{success, error}`), wallet_agent.js의 `POST /startLogin`(`{rpCredential, r_i, rpNonce}` → `202 {jobId}`), `GET /loginStatus?jobId=`(`{status}` 또는 `{status:'done', ppid, arid_i, auid_i, pk_i, publicKeyHex, pi_PPID, statement, idpToken}` — Task 2 완료 후의 shape), `POST /confirmLoginResult`(`{jobId, approved}`), Snap `confirmLogin`(params 없음, 반환 `{approved: boolean}`), 기존 `/api/mode2/wallet_agent_token`·`/api/mode2/rp_credential_nonce`(안 바뀜).
- Produces: 이 태스크가 마지막 코드 소비자이므로 이후 태스크에 새 인터페이스를 만들지 않는다. Task 5가 이 태스크 완료 후 `index.html`에서 안 쓰는 버튼을 지운다(이 태스크가 참조를 끊어놔야 함).

- [ ] **Step 1: `mode2SSOLoginButton` 핸들러 안의 `runWalletStep7()` 호출을 `runDelegatedLogin()`으로 교체**

`client.js:75`의 `await runWalletStep7();`를 `await runDelegatedLogin();`로 바꾼다.

- [ ] **Step 2: 이제 안 쓰는 상태 변수 정리**

`client.js:82-90`(`let currentSSOProof = null;`부터 `let mode2SessionNonce = null;` 바로 앞줄까지, 즉 `currentSSOProof`/`currentIdPToken`/`walletReceivedIdPToken`/`step11Completed`/`step13Completed`/`step14Result`/`measuredDurations`/`relayIframe`/`relayReady` 선언)을 지운다. `let mode2SessionNonce = null;`과 `let ssoMetadata = {...}`는 그대로 둔다.

- [ ] **Step 3: relay 관련 함수 제거**

`client.js`에서 `postProofToRelay`(163-167번 줄 부근), `clearIdPOnlyProofMaterial`(169-177번 줄 부근), `prepareWalletRelay`(179-193번 줄 부근) 세 함수 전체를 지운다.

- [ ] **Step 4: `runWalletStep7`/`openIdPLoginPopup`을 `runDelegatedLogin`/`runRpVerifyStatement`로 교체**

`client.js:195-347`(`getCurrentHeightForValidation`, `showWalletProcessSummary`, `runWalletStep7`, `openIdPLoginPopup` 네 함수 전체)을 지운다. `getCurrentHeightForValidation`은 옛 `runRPFeStep14`(Step 5에서 제거 대상)에서만 쓰이고 새 `runRpVerifyStatement`는 로컬 높이 체크를 하지 않으므로(서버의 `/api/mode2/verify_statement`가 `max_height`를 권위 있게 검증) 같이 제거해야 죽은 코드가 안 남는다. 지운 자리에 아래 두 함수를 추가한다:

```javascript
  async function runDelegatedLogin() {
    const start = now();
    mode2Status.innerText = 'Login job starting...';

    const tokenRes = await fetch('/api/mode2/wallet_agent_token');
    if (!tokenRes.ok) throw new Error('Could not fetch wallet agent token. Is wallet_agent.js running?');
    const { token: walletAgentToken } = await tokenRes.json();

    const startRes = await fetch(`${WALLET_AGENT_ORIGIN}/startLogin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': walletAgentToken },
      body: JSON.stringify({
        rpCredential: ssoMetadata.rpCredential,
        r_i: ssoMetadata.r_i,
        rpNonce: ssoMetadata.rpNonce,
      }),
    });
    if (startRes.status !== 202) {
      const errData = await startRes.json().catch(() => ({}));
      throw new Error(errData.error || `/startLogin failed (${startRes.status})`);
    }
    const { jobId } = await startRes.json();

    let snapConfirmSent = false;
    const POLL_INTERVAL_MS = 1000;

    await new Promise((resolve, reject) => {
      const timer = setInterval(async () => {
        try {
          const statusRes = await fetch(`${WALLET_AGENT_ORIGIN}/loginStatus?jobId=${encodeURIComponent(jobId)}`);
          if (!statusRes.ok) {
            clearInterval(timer);
            reject(new Error(`/loginStatus failed (${statusRes.status})`));
            return;
          }
          const data = await statusRes.json();

          switch (data.status) {
            case 'generating_proof':
              mode2Status.innerText = `Step 8: 지갑이 증명을 생성하는 중입니다... ${formatMs(start)}`;
              return;

            case 'awaiting_wallet_approval':
              mode2Status.innerText = 'Snap에서 로그인 승인을 기다리는 중입니다...';
              if (snapConfirmSent) return;
              snapConfirmSent = true;
              try {
                const snapResult = await window.ethereum.request({
                  method: 'wallet_invokeSnap',
                  params: { snapId, request: { method: 'confirmLogin', params: {} } },
                });
                await fetch(`${WALLET_AGENT_ORIGIN}/confirmLoginResult`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ jobId, approved: Boolean(snapResult?.approved) }),
                });
              } catch (err) {
                snapConfirmSent = false; // Snap 호출/보고 자체가 실패하면 다음 tick에 재시도
                console.warn('[Mode 2] Snap confirmLogin failed:', err.message);
              }
              return;

            case 'awaiting_browser_login':
              mode2Status.innerText = '시스템 브라우저에서 IdP 로그인을 진행해주세요.';
              return;

            case 'exchanging_token':
              mode2Status.innerText = '인증 코드를 토큰으로 교환하는 중입니다...';
              return;

            case 'done':
              clearInterval(timer);
              ssoMetadata.ppid = BigInt(data.ppid);
              ssoMetadata.arid_i = BigInt(data.arid_i);
              ssoMetadata.auid_i = BigInt(data.auid_i);
              ssoMetadata.pkI = data.pk_i;
              ssoMetadata.signingPublicKey = data.publicKeyHex;
              ssoMetadata.pi_PPID = data.pi_PPID;
              ssoMetadata.statement = data.statement;
              ssoMetadata.idpToken = data.idpToken;
              resolve();
              return;

            case 'denied':
              clearInterval(timer);
              reject(new Error('로그인이 거부되었습니다.'));
              return;

            case 'failed':
              clearInterval(timer);
              reject(new Error(data.error || '로그인에 실패했습니다.'));
              return;
          }
        } catch (err) {
          clearInterval(timer);
          reject(err);
        }
      }, POLL_INTERVAL_MS);
    });

    mode2Status.innerText = '로그인 완료. 결과를 검증하는 중입니다...';
    await runRpVerifyStatement(start);
  }

  async function runRpVerifyStatement(start) {
    const statement = ssoMetadata.statement;

    const ppidPublicSignals = ssoMetadata.pi_PPID?.publicSignals;
    const ridFromProof = ppidPublicSignals?.[0] != null ? BigInt(ppidPublicSignals[0]) : null;
    const ppidFromProof = ppidPublicSignals?.[1] != null ? BigInt(ppidPublicSignals[1]) : null;

    let piPpidOk = false;
    if (ssoMetadata.pi_PPID?.proof && Array.isArray(ppidPublicSignals) && ppidPublicSignals.length === 2) {
      try {
        const vkey = await getPiPpidVkey();
        piPpidOk = await snarkjs.groth16.verify(vkey, ppidPublicSignals, ssoMetadata.pi_PPID.proof);
      } catch (err) {
        console.warn('[Mode 2] pi_PPID ZKP verify error:', err.message);
      }
    }

    let ppidOk = false;
    let auidBindingOk = false;
    if (ridFromProof !== null && ppidFromProof !== null && ssoMetadata.rpNonceField != null) {
      ppidOk = String(ridFromProof) === String(ssoMetadata.rid);
      const recomputedAuidI = (ppidFromProof * ssoMetadata.rpNonceField) % FIELD_PRIME;
      auidBindingOk = String(statement?.auid_i) === String(recomputedAuidI);
    }

    const localChecksOk = auidBindingOk && ppidOk && piPpidOk;
    let rpBackendOk = false;
    let rpBackendMessage = localChecksOk ? 'not checked' : 'skipped because local checks failed';
    if (localChecksOk) {
      const res = await fetch('/api/mode2/verify_statement', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ statement, ppid: ssoMetadata.ppid.toString() }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        rpBackendOk = true;
        rpBackendMessage = 'PASS';
      } else {
        rpBackendMessage = data.error || 'RP backend verification failed';
      }
    }

    appendRpFeVisibleFlow('');
    appendRpFeVisibleFlow(`Statement 검증 ${formatMs(start)}`);
    appendRpFeVisibleFlow(`  auid_i / rp_nonce binding: ${auidBindingOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  rid binding: ${ppidOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  pi_PPID ZKP verification: ${piPpidOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  RP backend statement verification: ${rpBackendOk ? 'PASS' : 'FAIL'} (${rpBackendMessage})`);

    if (!localChecksOk || !rpBackendOk) {
      mode2Status.innerText = `로그인 검증 실패: ${rpBackendMessage}`;
      throw new Error(rpBackendMessage);
    }

    mode2Status.innerText = `로그인 성공 ${formatMs(start)}.`;
    const submitButton = document.getElementById('submitPPIDTransaction');
    if (submitButton) submitButton.disabled = false;
    const tracePkIInput = document.getElementById('traceInputPkI');
    const traceMaxHeightInput = document.getElementById('traceInputMaxHeight');
    if (tracePkIInput) tracePkIInput.value = ssoMetadata.pkI ?? '';
    if (traceMaxHeightInput) traceMaxHeightInput.value = statement?.max_height ?? '';
  }
```

- [ ] **Step 5: relay `message` 리스너 및 옛 디버그 버튼 핸들러 제거**

`client.js`에서 다음을 전부 지운다: `window.addEventListener('message', ...)`(`WALLET_AGENT_ORIGIN` 대상 relay 리스너), `document.getElementById('step25RPFEVerifyFail')?.addEventListener(...)`, `document.getElementById('step2SubmitToIdP')?.addEventListener(...)`, `document.getElementById('step25RPFEVerify')?.addEventListener(...)`, `verifyIdPTokenAtRpBackend` 함수 전체, `document.getElementById('step15NotifyWallet')?.addEventListener(...)`, `document.getElementById('step3CompleteRP')?.addEventListener(...)`, `runWalletStep11And12`, `runWalletStep12`, `runWalletStep13`, `runRPFeStep14`, `runRPFeStep15` 함수 전체.

`getPiPpidVkey`/`piPpidVkeyPromise`는 지우지 않는다(`runRpVerifyStatement`가 계속 쓴다).

- [ ] **Step 6: `submitPPIDTransaction` 핸들러 재배선**

기존 핸들러(`document.getElementById('submitPPIDTransaction')?.addEventListener('click', async () => {...})`) 안의 `fetch('http://127.0.0.1:5001/submitTransaction', ...)` 호출 부분(`body: JSON.stringify({...})`)만 아래로 교체한다. 나머지(토큰 획득, 배포 트랜잭션 처리, 영수증 대기, `loadTransactionHistory()` 갱신)는 그대로 둔다:

```javascript
        body: JSON.stringify({
          // 데모 고정값: 받는 사람/금액을 입력받는 폼은 이 기능 범위 밖.
          to: '0x000000000000000000000000000000000000dEaD',
          value: '0',
          data: '0x',
          business: {
            arid_i: ssoMetadata.arid_i.toString(),
            auid_i: ssoMetadata.auid_i.toString(),
            ppid: ssoMetadata.ppid.toString(),
            r_token: ssoMetadata.statement.r_token,
            chain_id: ssoMetadata.statement.chain_id,
            maxHeight: ssoMetadata.statement.max_height,
          },
          rpNonce: ssoMetadata.rpNonce,
          idpToken: ssoMetadata.idpToken,
        }),
```

- [ ] **Step 7: 문법 검사**

Run: `node --check client.js`
Expected: 출력 없이 종료(문법 오류 없음).

- [ ] **Step 8: 수동 브라우저 테스트**

`node server.js`(3000), `node custom_idp.js`(4000), `node wallet_agent.js`(5001)를 띄우고(이미 떠 있다면 재시작 불필요), `index.html`을 MetaMask+Snap이 연결된 브라우저로 연다.

1. **골든 패스**: "Delegated Login" 클릭 → Snap `confirmLogin` 승인 팝업이 뜨면 승인 → 시스템 브라우저가 열리고 IdP 로그인 폼이 뜨면 `testuser`/`password123`으로 로그인 후 동의 → 탭이 "Login complete" 메시지로 바뀌고 원래 페이지로 돌아오면 `mode2Status`에 "로그인 성공"이 뜨고 `rpFeVisibleFlowLog`에 4개 PASS 줄이 보이는지, "Send PPID Transaction" 버튼이 활성화되는지 확인. 버튼을 눌러 트랜잭션이 실제로 제출되고 `traceHistorySelect`에 새 항목이 뜨는지까지 확인.
2. **Snap 거부**: 같은 과정을 반복하되 Snap `confirmLogin` 팝업에서 취소를 눌러, `mode2Status`에 "로그인이 거부되었습니다."가 뜨는지 확인.
3. **IdP 로그인 취소**: Snap은 승인하되 시스템 브라우저에서 IdP 로그인/동의를 거부(또는 탭을 그냥 닫음)해서, `mode2Status`에 적절한 실패 메시지가 뜨는지 확인.

CLAUDE.md 규칙대로, 이 수동 테스트를 위해 새로 띄운 프로세스는 테스트가 끝나면 포트(3000/4000/5001)를 정리한다(사용자가 이미 띄워둔 프로세스라면 확인 후 처리).

- [ ] **Step 9: 커밋**

```bash
git add client.js
git commit -m "feat(mode2): wire client.js to the new loopback job-polling login flow"
```

---

### Task 5: index.html 정리 + 옛 팝업/relay 파일 삭제

**Files:**
- Modify: `index.html:37-52`
- Delete: `idp/login_popup.html`, `idp/login_popup.js`, `wallet/relay.html`, `wallet/relay.js`

**Interfaces:**
- Consumes: Task 4 완료 후 `client.js`가 더 이상 `#step2SubmitToIdP` 등 디버그 버튼이나 `wallet/relay.*`, `idp/login_popup.*`를 참조하지 않는 상태.
- Produces: 없음(정리 태스크, 마지막 태스크).

- [ ] **Step 1: `index.html`에서 디버그 버튼 블록 삭제**

`index.html:37-52`(`<div id="ssoStepButtons" ...>`부터 그 짝 `</div>`까지)를 통째로 지운다. `rpFeVisibleFlow`/`ssoDataDisplay` div는 그대로 둔다.

- [ ] **Step 2: 옛 팝업/relay 파일 삭제**

```bash
rm idp/login_popup.html idp/login_popup.js wallet/relay.html wallet/relay.js
```

`custom_idp.js:504-507`의 `GET /login_popup` 라우트, `wallet_agent.js:353-359`의 `GET /relay` 라우트/`/wallet` 정적 서빙은 이 삭제로 인해 요청이 오면 404/에러를 반환하게 되지만, 이번 계획 범위 밖(Global Constraints 참고)이라 그대로 둔다 — 아무도 더 이상 이 경로를 호출하지 않으므로 실질적 영향은 없다.

- [ ] **Step 3: 남은 참조 확인**

Run: `grep -rn "login_popup\|wallet/relay" client.js index.html server.js wallet_agent.js custom_idp.js`
Expected: `custom_idp.js`의 `GET /login_popup` 라우트 정의 한 줄(위에서 의도적으로 남긴 죽은 라우트)과 `wallet_agent.js`의 `GET /relay` 관련 줄들만 나오고, `client.js`/`index.html`에는 아무 것도 안 나와야 한다.

- [ ] **Step 4: 브라우저에서 `index.html` 로드 확인**

`server.js`를 띄운 채(또는 정적 서빙 경로로) `index.html`을 브라우저로 열어, "Delegated Login"/"Send PPID Transaction"/"Trace Transaction"/"Refresh" 버튼만 보이고 옛 Step 9/11/12/14/Fail Test 버튼이 안 보이는지 눈으로 확인한다. 콘솔에 404나 참조 에러가 없는지도 확인한다.

- [ ] **Step 5: 커밋**

```bash
git add -u index.html idp/login_popup.html idp/login_popup.js wallet/relay.html wallet/relay.js
git commit -m "chore(mode2): remove obsolete popup/relay files and debug step buttons"
```

(`git add -u`는 삭제된 파일을 스테이징하기 위함 — 이 5개 경로로 범위를 한정했으므로 다른 변경은 섞이지 않는다.)
