# RP FE(client.js) + server.js Statement 검증 — 설계 문서

## 1. 개요

Wallet-IdP 통신 재설계(팝업/postMessage relay → PAR+Authorization Code+PKCE+loopback redirect)의 마지막 서브프로젝트다.

- **서브프로젝트 1** (완료, 커밋 dd6c3e4~e15090c): `custom_idp.js`에 `POST /par`, `GET/POST /authorize`, `POST /token` 신설. 기존 `/register_rp`·`/sso_with_credentials`·`/consent_result`는 병행 유지.
- **서브프로젝트 2** (완료, 커밋 b6f72f7~e59946c): `wallet_agent.js`에 `POST /startLogin`, `GET /loginStatus`(job 폴링), `POST /confirmLoginResult`, loopback HTTP 리스너, 시스템 브라우저 실행 추가. Snap에 `confirmLogin` 승인 다이얼로그 추가.
- **서브프로젝트 3** (본 문서): `client.js`를 새 job-폴링 API + Snap 호출로 연결하고, `server.js`에 새 9-field "PairCT signed login statement" 검증 로직을 추가하고, 이제 안 쓰게 되는 옛 팝업/relay 코드를 제거한다. 브레인스토밍 과정에서 발견된 하위 호환성 문제(§4) 때문에 `custom_idp.js`·`wallet_agent.js`에도 작은 추가가 필요하다.

서브프로젝트 1의 스펙에 이미 명시된 대로, 새 9-field statement 포맷을 실제로 검증하는 코드는 IdP·Wallet 어느 쪽에도 없다 — RP FE가 새 흐름으로 로그인을 완주하려면 `server.js`에 이 검증 로직이 반드시 있어야 한다.

## 2. 목표 / 비목표

**목표**
- `client.js`가 `wallet_agent.js`의 `/startLogin` → `/loginStatus`(폴링) → (Snap 승인 시) `/confirmLoginResult` 흐름을 사용해 로그인을 완주한다.
- `server.js`가 새 9-field statement(`{iss,aud,nonce,arid_i,auid_i,r_token,max_height,chain_id,exp,signature:{R8,S}}`)를 독립적으로 검증해서 RP 세션을 수립한다.
- `custom_idp.js`의 `/token`이 새 statement와 별도로 옛 6-field `IDP_TOKEN` 서명도 반환하고, `wallet_agent.js`가 그 값을 job 결과에 포워딩해서, `client.js`의 "Send PPID Transaction"(온체인 tx 제출)이 새 로그인 흐름을 거친 뒤에도 계속 동작한다(§4 참고).
- 이제 안 쓰는 팝업/relay 코드(`client.js`, `idp/login_popup.*`, `wallet/relay.*`)와 `index.html`의 단계별 디버그 버튼을 제거한다.

**비목표 (이번 서브프로젝트 범위 밖)**
- `pi_pk_i.circom` 회로 자체를 새 9-field/도메인 서명을 검증하도록 바꾸는 것 — 온체인에 이미 배포된 `PiPkIVerifier`/`PPIDWalletFactory`(불변, 신뢰 IdP 키 내장)를 재배포해야 해서 스코프가 훨씬 크다. §4에서 채택한 "옛 포맷 서명도 같이 발급" 방식으로 회로/온체인 컨트랙트는 전혀 안 건드린다.
- `wallet_agent.js`의 `/relay` 라우트(정적 서빙), `POST /verifyIdPAuthToken`(옛 Step 12 검증) 제거 — client.js가 더 이상 호출하지 않아 죽은 코드가 되지만, 이번 서브프로젝트의 wallet_agent.js 변경은 §4의 최소 추가(job.result 필드 포워딩)로 한정한다. 나머지 정리는 후속으로 남긴다.
- `custom_idp.js`의 `/register_rp`·`/sso_with_credentials`·`/consent_result`(옛 흐름) — 그대로 둔다. 옛 흐름 자체를 폐기할지는 이번 문서의 범위가 아니다.
- PAR TTL(60초) 등 서브프로젝트 1에서 이미 나중으로 미룬 튜닝 항목.

## 3. client.js 설계

### 3.1 변경 없이 유지되는 부분

`mode2SSOLoginButton` 클릭 핸들러의 앞부분은 그대로 유지한다:
1. `connectSnap()`
2. `POST /api/mode2/rp_credential_nonce` 호출 → `ssoMetadata.rpCredential`, `ssoMetadata.sessionNonce`, `ssoMetadata.r_i`, `ssoMetadata.rpNonce` 저장
3. `mode2SessionNonce` 생성, `rpFeVisibleFlowLog`에 Step 1~7 로그 기록

이 뒤에서 `await runWalletStep7();` 호출을 `await runDelegatedLogin();`으로 교체한다.

### 3.2 신규: `runDelegatedLogin()`

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
            ssoMetadata.idpToken = data.idpToken; // 옛 6-field 포맷 — /submitTransaction 전용 (§4 참고)
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
```

`mode2SSOLoginButton` 핸들러의 catch 블록은 그대로 두되(에러 메시지를 `mode2Status`에 표시하고 버튼을 다시 활성화), `runDelegatedLogin()`이 던지는 에러도 동일하게 잡힌다.

### 3.3 신규: `runRpVerifyStatement(start)`

옛 `runRPFeStep14()`가 하던 역할(로컬 pi_PPID 검증 + RP 백엔드 검증 + `rpFeVisibleFlowLog` 기록 + 버튼 활성화)을 새 statement 포맷 기준으로 재구성한다. pi_PPID의 RP FE 로컬 Groth16 검증은 유지한다(서버가 statement 서명/audience를 검증해도, pi_PPID는 uid/rid/salt에 대한 별도 증명이라 커버리지가 다르다).

```javascript
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

`getPiPpidVkey()`는 그대로 유지한다.

### 3.4 `submitPPIDTransaction` 재배선

기존 핸들러는 `currentSSOProof?.business`와 `walletReceivedIdPToken`을 참조하는데, 둘 다 제거되므로(§3.5) `ssoMetadata`에서 직접 조립한다. `/submitTransaction`이 실제로 읽는 필드(`business.arid_i`, `business.auid_i`, `business.PPID`/`business.ppid`, `business.r_token`/`business.tokenNonce`, `business.chain_id`/`business.chainId`, `business.maxHeight`/`business.max_height`, `idpToken.signature.{R8,S}`)를 기준으로 맞춘다:

```javascript
const submitRes = await fetch('http://127.0.0.1:5001/submitTransaction', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
  body: JSON.stringify({
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
});
```

나머지(배포 트랜잭션 처리, 영수증 대기, `loadTransactionHistory()` 갱신)는 그대로 유지한다.

### 3.5 제거 대상

함수: `postProofToRelay`, `prepareWalletRelay`, `clearIdPOnlyProofMaterial`, `runWalletStep7`, `openIdPLoginPopup`, `showWalletProcessSummary`, `verifyIdPTokenAtRpBackend`, `runWalletStep11And12`, `runWalletStep12`, `runWalletStep13`, `runRPFeStep14`, `runRPFeStep15`.

리스너: `window.addEventListener('message', ...)`(relay origin 대상), `#step25RPFEVerifyFail`, `#step2SubmitToIdP`, `#step25RPFEVerify`, `#step15NotifyWallet`, `#step3CompleteRP`의 클릭 핸들러.

상태 변수: `currentSSOProof`, `currentIdPToken`, `walletReceivedIdPToken`, `step11Completed`, `step13Completed`, `step14Result`, `relayIframe`, `relayReady`, `measuredDurations`(Step 8/12/14/15 세분 타이밍 — 새 흐름엔 대응 단계가 없어 제거).

유지: `ssoMetadata`, `appendWalletLog`, `appendRpFeVisibleFlow`, `previewValue`, `formatMs`/`formatDurationMs`, `valueToField`, `FIELD_PRIME`, `getPiPpidVkey`/`piPpidVkeyPromise`, `loadTransactionHistory`/`traceTransaction`/`refreshTraceHistory` 핸들러(트랜잭션 제출/추적 기능은 이번 변경과 무관, `submitPPIDTransaction`은 §3.4 기준으로 내부만 재배선).

## 4. custom_idp.js / wallet_agent.js — 옛 포맷 idpToken 병행 발급

**문제**: `wallet_agent.js`의 `/submitTransaction`은 `req.body.idpToken.signature.{S,R8}`를 `pi_pk_i` 회로 입력에 그대로 사용한다. 이 회로는 온체인에 이미 배포된 `PiPkIVerifier`(불변, 신뢰 IdP 키 내장)에서 검증되며, 내부적으로 **옛 6-field `IDP_TOKEN` 도메인** 메시지(`[DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]`)를 재구성해서 서명을 확인한다. 새 `/token`이 발급하는 statement의 서명은 **9-field `PAIRCT_STATEMENT` 도메인**이라 그대로 넣으면 검증이 깨진다. 회로/온체인 컨트랙트를 바꾸는 대신, IdP가 같은 값들로 옛 포맷 서명도 하나 더 만들어서 함께 내려준다.

### 4.1 `custom_idp.js`의 `/token` 응답에 `idpToken` 필드 추가

기존 `msgFields`(9-field, `DOMAIN_PAIRCT_STATEMENT`)와 그 서명(`signature`)은 그대로 둔다. 그 아래에 옛 포맷 서명을 추가로 계산해서 응답에 얹는다:

```javascript
// 기존 9-field statement 서명(res.json() 이전)에 이어서:
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
```

이 메시지 구성(`DOMAIN_IDP_TOKEN` + 6-field)은 `server.js`의 옛 `sso_success`, `wallet_agent.js`의 옛 `verifyIdPAuthToken`이 이미 쓰는 것과 동일한 패턴이라 새로운 서명 방식을 도입하는 게 아니다 — 이미 있던 값들로 같은 서명을 한 번 더 만드는 것뿐이다.

### 4.2 `wallet_agent.js`의 `job.result`에 `idpToken` 포워딩

`exchangeToken()`에서 `/token` 응답(`statement`)을 받은 뒤, 그 안에 얹혀 온 `idpToken` 서브필드를 분리해서 `job.result`의 별도 필드로 옮긴다(그냥 `statement` 전체를 복사하면 `job.result.statement.idpToken`이라는 중복 중첩이 생기므로, 구조 분해로 분리한다):

```javascript
const { idpToken, ...statementFields } = statement;
job.result = {
  ppid: step8.ppid,
  arid_i: step8.arid_i,
  auid_i: step8.auid_i,
  pk_i: step8.pk_i,
  publicKeyHex: step8.publicKeyHex,
  pi_PPID: step8.pi_PPID,
  statement: statementFields,
  idpToken, // 신규: /submitTransaction용 옛 포맷 서명
};
```

`/loginStatus`의 `done` 응답(`res.json({ status: 'done', ...job.result })`)이 이미 `job.result`를 그대로 펼치므로, 이 한 줄 추가로 `client.js`가 `data.idpToken`을 받을 수 있게 된다. 이 변경 외에 `wallet_agent.js`의 다른 로직(`/startLogin`, `/loginStatus`, `/confirmLoginResult`, loopback 리스너)은 건드리지 않는다.

## 5. server.js 설계 — `POST /api/mode2/verify_statement`

기존 `/api/mode2/sso_success`는 전혀 수정하지 않고 병행 추가한다.

**요청**: `{ statement, ppid }`
- `statement`: wallet_agent.js `/loginStatus`의 `done` 응답 중 `statement` 필드 — `{iss, aud, nonce, arid_i, auid_i, r_token, max_height, chain_id, exp, signature:{R8,S}}`. `idpToken`(옛 포맷, `/submitTransaction` 전용)은 `job.result`의 별도 필드로 분리되어 있으므로(§4.2) 여기엔 섞여 있지 않다.
- `ppid`: 10진 문자열. B2 추적 기록(`walletAddressToAuidI`)에만 사용.

**검증 순서**:
1. `assertCanonicalField`로 `statement.arid_i`, `statement.auid_i`, `statement.r_token`, `statement.max_height`, `statement.chain_id` 형식 확인. `statement.signature.R8`(길이 2 배열), `statement.signature.S` 존재 확인. (`/api/mode2/sso_success`의 동일 패턴 재사용)
2. `statement.iss === 'custom-idp'` 확인 (`custom_idp.js`가 `/token`에서 하드코딩하는 값과 동일하게 서버 쪽도 상수로 하드코딩).
3. `statement.aud === 'pairct-wallet'` 확인 (`custom_idp.js`의 `PAIRCT_CLIENT_ID`와 동일 문자열).
4. Audience 체크(RP 자신의 책임, 기존 로직 그대로): `rpRegistration.rid`와 `req.session.rpNonce`로 `expectedAridI = (valueToField(rid) * valueToField(sessionRpNonce)) % FIELD_PRIME` 재계산 후 `statement.arid_i`와 문자열 비교. 불일치 시 403.
5. `chain_id` 체크: `getRpcChainId()`와 `statement.chain_id` 비교(기존 로직 그대로).
6. `max_height` 체크: `getCurrentHeightForToken()`으로 얻은 현재 높이가 `statement.max_height`를 넘으면 401(기존 로직 그대로). `statement.exp`는 서명 메시지에 포함되지 않는 비서명 필드이므로 만료 판단에 쓰지 않는다(§6 참고).
7. 서명 검증: 9-field 메시지를 재구성한다.
   ```javascript
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
   ```
   `rawIdpPublicKeys.pk_IdP`로 `eddsa.verifyPoseidon(msg, sigForVerify, pkIdP)` 검증(기존 `verifyRpRegSignature`/`sso_success`와 동일한 `eddsa.F.e(BigInt(...))` 변환 패턴).
8. 성공 시: `computeWalletAddress(ppid)` → `walletAddressToAuidI.set(walletAddress.toLowerCase(), statement.auid_i)`(기존 로직 그대로), `delete req.session.rpNonce`(single-use 소진), `res.json({ success: true })`.

각 단계 실패 시 `/api/mode2/sso_success`와 동일한 스타일의 상태 코드/에러 메시지를 사용한다(400/401/403/500/503).

## 6. 설계 노트 (구현 시 유의)

- **`statement.exp`는 신뢰하지 않는다.** `/token` 핸들러의 서명 대상 `msgFields`에 `exp`가 없다(코드 확인 완료) — 즉 위조해도 서명이 깨지지 않는다. 옛 idpToken도 같은 특성을 가졌고 그때도 `max_height`만 권위 있는 만료 기준으로 썼다. 일관성을 위해 이번에도 `exp`는 화면 표시 등 참고용으로만 쓰고 검증에는 안 쓴다.
- **`statement.nonce`는 RP가 대조할 방법이 없다.** 이 값은 `wallet_agent.js`의 loopback 내부에서 생성되어 RP FE에 사전 전달된 적이 없다. 옛 흐름의 `r_i` 에코 체크(팝업이 응답한 `r_i`가 RP FE가 시작한 세션과 같은지)는 이제 `jobId`가 세션을 스코프하므로 불필요하다 — `jobId`는 RP FE가 `/startLogin` 호출로 직접 발급받은 값이고, `/loginStatus` 폴링은 그 `jobId`로만 결과를 가져오므로 다른 세션의 응답이 섞일 수 없다.
- **`idpToken`(옛 포맷)과 `statement`(새 포맷)는 서로 다른 목적이다.** `statement`는 RP 세션 수립(`server.js`)에, `idpToken`은 온체인 tx 제출(`wallet_agent.js`의 `/submitTransaction`, `pi_pk_i` 회로)에 각각 쓰인다. 한쪽을 다른 쪽 용도로 섞어 쓰면 안 된다(도메인 분리자가 다르므로 섞으면 서명 검증 자체가 실패한다).

## 7. 정리 대상 파일

- 삭제: `idp/login_popup.html`, `idp/login_popup.js`, `wallet/relay.html`, `wallet/relay.js`(구현 착수 시 실제 존재 여부/경로 재확인).
- `index.html`: `ssoStepButtons` div(4개 디버그 버튼 + Fail Test 버튼) 전체 삭제. `rpFeVisibleFlow`/`rpFeVisibleFlowLog`, `ssoDataDisplay`(있다면 유사 요소)는 새 흐름의 상태 로그 용도로 유지.
- 이번 스코프 밖(후속 정리로 남김, §2 비목표 참고): `wallet_agent.js`의 `/relay` 라우트, `POST /verifyIdPAuthToken`.

## 8. 테스트 계획

- 기존 패턴을 따라 `test_*.js` 스타일의 통합 테스트를 신규 작성: `custom_idp.js`+`wallet_agent.js`+`server.js`를 띄우고
  - `/token`이 `statement`와 `idpToken`(옛 포맷) 둘 다 유효한 서명으로 반환하는지
  - `/api/mode2/verify_statement`가 정상 statement는 통과시키고, `iss`/`aud` 변조, `arid_i` 불일치(다른 RP), 서명 변조, `max_height` 초과 각각을 거부하는지
  - `/submitTransaction`이 새 흐름에서 받은 `idpToken`으로 `pi_pk_i` 증명을 정상 생성하는지(회로/컨트랙트 자체는 안 바뀌므로 기존 온체인 검증 경로가 그대로 통과해야 한다)
  를 확인한다.
- `client.js`는 브라우저 기반이라 자동화 테스트 대상이 아니었던 기존 관례를 따라, 실제 MetaMask+Snap 환경에서 수동으로 골든 패스(로그인 성공 → Send PPID Transaction 성공) + 거부(Snap에서 취소) + IdP 로그인 취소 3가지를 확인한다.
