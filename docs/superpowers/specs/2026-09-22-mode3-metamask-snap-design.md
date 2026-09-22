# Mode 3 — MetaMask/Snap 구색 설계: Snap 이 등록 비밀·동의 창, 지갑 페이지가 단일 dapp, MetaMask 가 트랜잭션 전송

**상태: 초안. 사용자 검토 대기.**
작성 2026-09-22. 브레인스토밍 결정(사용자): ①증명은 에이전트가 만들되 증인은 요청마다 Snap 에서 받아 메모리에서만 쓴다,
②세션키는 에이전트의 임시 키·트랜잭션 전송만 MetaMask, ③Snap 은 등록 비밀만 보관하고 동의 창 3종 + uid·비밀번호 입력 대화상자,
④Snap 을 부르는 dapp 은 지갑 페이지(:5100) 하나이고 RP 는 팝업으로 연다.

기반 문서: `2026-09-22-mode3-selective-disclosure-design.md`(V6, 이하 "선택 공개"), `2026-09-21-mode3-two-tier-credential-design.md`(이중 구조),
`2026-09-18-mode3-onchain-execution-design.md`(온체인 실행), Mode 2 의 `snap/`(Snap 빌드·권한 관례). 이 문서는 지갑 에이전트의
**비밀 저장 위치와 사용자 동의 지점**, RP 페이지의 **지갑 호출 방식**을 바꾼다. 회로·컨트랙트·CIA·서비스 서버 로직·증명 형식은
바뀌지 않는다.

---

## 1. 무엇이 달라지는가

| | 지금 | 이 문서 |
|---|---|---|
| 등록 비밀(uid, s_u, r_u, sk_u, blind_u, attrs, cm_u) | 에이전트 상태 파일 `mode3_wallet_state.json` | **Snap 상태**(`snap_manageState`). 에이전트는 파일에 쓰지 않고 요청 처리 중 메모리에만 |
| 세션(sk_i, blind_s, σ_AA, 증명 캐시) | 에이전트 상태 파일 | 그대로 에이전트 |
| 사용자 동의 | 없음(자동 처리) | Snap 대화상자: 로그인 동의, 속성 공개 동의, 등록·자기 폐기 입력. 트랜잭션은 MetaMask 확인 창 |
| RP → 지갑 | RP 페이지가 에이전트를 CORS 로 직접 호출 | 로그인(비밀 필요)은 RP 페이지가 **지갑 페이지 팝업**(`/authorize`)을 열고 `postMessage` 로 결과를 받음. 재검증·세션 요청(비밀 불필요)은 지금처럼 CORS 호출 유지 |
| 트랜잭션 전송 | 릴레이어(hardhat 언락 계정) | **MetaMask** `eth_sendTransaction`(사용자 EOA 가 가스). 릴레이어는 `file` 모드에만 남김 |
| 비밀 공급원 | 파일 고정 | `SecretSource` 추상화: `snap`(브라우저 데모) / `file`(자동 테스트·헤드리스 데모). 환경변수 `MODE3_WALLET_SECRETS` |
| Snap 패키지 | Mode 2 `snap/`(PS·mcl) | **새 패키지 `snap-mode3/`**. Mode 2 Snap 은 건드리지 않음 |

**목적.** Mode 2 가 갖춘 "Connect Wallet → 동의 창 → MetaMask 트랜잭션" 구색을 Mode 3 에 맞게 만든다. 데모 한계였던 "지갑 UI 확인
대화상자 없음"(선택 공개 §7, 후속 4번)을 닫고, 등록 비밀을 Node 프로세스 파일이 아닌 MetaMask 보관소에 둔다.

**바뀌지 않는 것.** π_u·π_rp·σ_AA·PPID·리프·태그·공개 입력 23개·`Mode3Wallet`·`AttrGate`·CIA 엔드포인트·서비스 로그인 검증. RP
프런트엔드는 여전히 uid·s_u 를 보지 못한다.

---

## 2. 가정과 신뢰

- **Snap 상태는 MetaMask 가 암호화해 보관한다.** 등록 비밀의 영속 저장은 Snap 에만 있다. 에이전트 프로세스는 요청 처리 중(그리고 §4.3 의
  세션 동안) 메모리에 증인을 들지만 디스크에 쓰지 않는다. 따라서 "Snap 이 보관"은 영속 저장에 대한 보증이지 프로세스 메모리에 대한
  보증이 아니다(문서·논문에 그렇게 적는다).
- **지갑 페이지(:5100)는 에이전트와 같은 오리진**이라 신뢰 경계가 하나다. Snap 은 이 오리진의 호출만 받는다(`onRpcRequest` 의 `origin`
  검사). RP 오리진은 Snap 을 부를 수 없다.
- **RP 페이지는 팝업 결과만 본다.** 결과는 `{ ok, PPID, pk_i, r_s, root, allowAgent }` — 지금 `/wallet/login` 응답과 같은 공개 값이다.
  팝업은 `postMessage` 대상 오리진을 요청에 실린 `origin` 으로 고정하고, RP 페이지는 `event.origin === walletAgentOrigin` 을 검사한다.
- **MetaMask 가 보내는 트랜잭션의 발신자는 사용자 EOA** 이므로 체인에서 EOA ↔ PPID 계정이 이어진다. Mode 2 와 같은 데모 한계로 문서화한다.
  릴레이어 경로(`file` 모드)는 이 연결이 없다.
- **MetaMask Flask** 에 로컬 Snap(`local:http://localhost:8082`)을 설치해 데모한다. 실제 배포의 npm 게시·감사는 범위 밖.
- honest-but-curious AA·서비스, 능동적 AA 부정, 셋업 한계 등 기존 가정은 그대로.

---

## 3. 구성 요소

### 3.1 Snap `snap-mode3/`

- 빌드: Mode 2 `snap/` 과 같은 `@metamask/snaps-cli`(`mm-snap build`, `mm-snap serve`), 포트 **8082**(Mode 2 는 8081). `snap.manifest.json`
  권한: `endowment:rpc { dapps: true }`, `snap_dialog`, `snap_manageState`. `endowment:ethereum-provider`·`network-access`·`webassembly` 는
  필요 없다(체인·CIA 통신은 에이전트, 증명은 에이전트). 암호 계산은 Baby Jubjub·Poseidon 으로 s_u·r_u·cm_u 생성을 한다 —
  **`circomlibjs` 는 쓰지 않는다**(WASM 이 필요해 `endowment:webassembly` 없는 manifest 와 충돌한다. §9(c) — 대신 점 연산을
  `snap-mode3/src/crypto.js` 에 BigInt 로 직접 적고 루트 `lib` 의 `registrationCommit` 과 같은 점인지 테스트로 고정했다).
- 상태(`snap_manageState`, 암호화 저장):
  ```
  { version: 1,
    registration: { uid, pwdHash?: null, s_u, r_u, cm_u:{x,y}, sk_u, attrs:[4], registeredAt } | null,
    userCred: { C_u_pt:{x,y}, Cf_u, blind_u, leaf, issuedAt } | null,
    consents: { [origin]: { arid, allowAgent, grantedAt } } }
  ```
  비밀번호는 저장하지 않는다(`pwdHash` 는 두지 않음 — 등록·자기 폐기 때만 입력받아 즉시 넘긴다).
- RPC(모두 호출 오리진이 `WALLET_ORIGIN` 이 아니면 거절):

  | method | 대화상자 | 반환 |
  |---|---|---|
  | `register` | prompt ×2: uid, 비밀번호. 이미 등록돼 있으면 거절 | `{ uid, pwd, cm_u }` — s_u·r_u 는 생성해 상태에 저장 |
  | `storeRegistration({ sk_u, attrs })` | 없음 | `{ ok }` — 등록 응답을 저장 |
  | `getPublicInfo` | 없음 | `{ registered, uid, cm_u, attrs, hasUserCred, consents }` (비밀 없음) |
  | `consentLogin({ origin, arid, allowAgent, serviceName })` | confirmation: "서비스 {name}({origin}, arid …)에 로그인할까요? AI 에이전트 허용: 예/아니오" | 승인 시 **증인 묶음** `{ uid, s_u, r_u, sk_u, attrs, userCred }`; 거절 시 `{ denied: true }`. 승인은 `consents[origin]` 에 기록 |
  | `consentDisclosure({ arid, origin, disclose:[{lo,hi}|null×4], to, value })` | confirmation: 슬롯별 "a₀(출생연도) ∈ [0, 2007]" 목록 + 대상 주소·금액 | `{ ok }` 또는 `{ denied: true }` |
  | `updateUserCred({ C_u_pt, Cf_u, blind_u, leaf })` | 없음 | `{ ok }` — 에이전트가 새 C_u 를 받았을 때 |
  | `syncAttrs({ attrs })` | 없음 | `{ ok, changed }` |
  | `selfRevoke` | prompt: 비밀번호 | `{ uid, pwd }` |
  | `reset` | confirmation: "등록을 지웁니다" | `{ ok }` — 데모 초기화용 |

  증인 묶음은 `consentLogin` 응답으로만 나간다. `getPublicInfo` 는 비밀을 절대 싣지 않는다.

### 3.2 지갑 페이지 `mode3/wallet.html`(:5100)

- 상단 "MetaMask 연결" 버튼: `eth_requestAccounts` → 계정 표시; `wallet_requestSnaps({ [SNAP_ID]: {} })` → Snap 설치·연결 표시.
  `SNAP_ID` 는 에이전트 `/wallet/config` 가 준다(`MODE3_SNAP_ID`, 기본 `local:http://localhost:8082`).
- 등록: Snap `register` → 에이전트 `POST /wallet/register { uid, pwd, cm_u }` → 응답 `{ sk_u, attrs }` 를 Snap `storeRegistration` 으로 저장.
  에이전트는 `snap` 모드에서 sk_u·attrs 를 파일에 쓰지 않는다.
- `/authorize` 팝업 화면(같은 파일, `?authorize=1` 로 모드 전환). **요청은 쿼리가 아니라 `postMessage` 로 받는다** — 오리진 검증을
  위해서다: 팝업이 열리면 `window.opener.postMessage({ type:'mode3-authorize-ready' }, '*')` 를 보내고, RP 페이지가
  `{ type:'mode3-authorize', arid, origin, cert_s, pk_trace, r_s, allowAgent, factoryAddress, attrGateAddress, serviceName }` 를 답한다.
  팝업은 `event.origin === request.origin` 일 때만 진행한다(피싱 페이지는 남의 arid·cert_s 를 보여줄 수는 있어도 인증서의 오리진에서
  메시지를 보낼 수는 없다 — 지금 `/wallet/login` 의 `Origin` 헤더 검사와 같은 방어). 이후 에이전트 `POST /wallet/authorize/precheck`
  (인증서·팩토리 검증) → Snap `consentLogin` → 에이전트 `POST /wallet/login` 에 요청 + `witness` + `verifiedOrigin` 첨부 → 응답을
  `window.opener.postMessage({ type:'mode3-authorize-result', r_s, result }, request.origin)` → 창 닫기. 새 사용자 자격증명이 응답에
  있으면(`userCredIssued`) Snap `updateUserCred`, `attrsChanged` 면 Snap `syncAttrs`. 거절·실패도 같은 형식으로 알린다.
- 트랜잭션 폼: 공개 슬롯 선택 → Snap `consentDisclosure` → 에이전트 `POST /wallet/tx/prepare` → `{ to: walletAddr, data: executeCalldata,
  value: 0 }` 를 `eth_sendTransaction` 으로 MetaMask 에 → 영수증 해시를 에이전트 `POST /wallet/tx/record { r_s, txHash }` 에 → 에이전트가
  영수증을 파싱해 기존 응답 형식(`executed`, `disclosure`, `onchainDisclosure`)으로 돌려준다.
- 자기 폐기: Snap `selfRevoke` → 에이전트 `POST /wallet/self_revoke { uid, pwd }`(**T6 에서 새로 만든 프록시** — 초안은 이것을
  기존 경로로 적었지만 에이전트에 그 라우트가 없었다. §9 Ruling 7).

### 3.3 지갑 에이전트 `mode3_wallet_agent.js`

- **`SecretSource`**(새 파일 `lib/mode3_secret_source.js`):
  ```
  interface SecretSource {
    mode: 'snap' | 'file'
    registration(): { uid, s_u, r_u, sk_u, attrs, cm_u } | null   // 비밀 포함
    userCred(): { C_u_pt, Cf_u, blind_u, leaf } | null
    setRegistration(reg), setUserCred(uc), setAttrs(attrs)
  }
  ```
  - `file`: 지금 상태 파일 그대로(`registration`, `registration.userCred`).
  - `snap`: 요청에 첨부된 `witness` 로 **요청 범위 `SecretSource` 를 만든다**. `setUserCred`·`setAttrs` 는 응답에 `userCredIssued`·
    `attrsChanged` 로 실어 페이지가 Snap 에 저장하게 한다(에이전트는 Snap 을 못 부른다). 파일에는 `registration` 을 **공개 부분만**
    (`uid`, `cm_u`, `attrs`, `userCred` 의 `Cf_u`·`leaf`) 둔다 — `/wallet/status` 와 세션 무결성 검사에 필요하다.
- **세션 동안 메모리 보유(사용자 결정 ③·§4.3).** `snap` 모드에서 로그인 성공 시 에이전트는 그 세션의 `{ s_u, blind_u, attrs, sk_u }` 를
  `sessions[r_s].witness` 에 **메모리에만** 둔다(`persist()` 가 `witness` 를 제외하고 쓴다). 재검증·재증명·`/wallet/tx/prepare` 는 이것을
  쓴다. 프로세스 재시작 후에는 없으므로 `/wallet/revalidate` 가 `409 needs_consent` 를 돌려주고 RP 페이지가 팝업을 다시 연다.
- 엔드포인트 변경:
  - `POST /wallet/register { uid, pwd, cm_u }` (`snap` 모드: cm_u 를 페이지가 줌; `file` 모드: 지금처럼 에이전트가 생성). 응답에 `sk_u`,
    `attrs` 를 실어 페이지가 Snap 에 저장(`file` 모드는 파일에 저장, 응답에 sk_u 없음).
  - `POST /wallet/authorize/precheck { arid, origin, cert_s, pk_trace, factoryAddress }` → `{ ok }` 또는 `{ reason }` — 지금 `/wallet/login`
    의 인증서·오리진·팩토리 검사만 떼어 낸 것.
  - `POST /wallet/login`: `snap` 모드에서 본문 `witness` 필수(`{ uid, s_u, r_u, sk_u, attrs, userCred }`); 없으면 `400 witness_required`.
    같은 오리진(지갑 페이지)에서 오는 요청은 `Origin` 헤더 대신 본문 `verifiedOrigin`(팝업이 `postMessage` 의 `event.origin` 으로 확인한
    값)을 인증서 오리진과 대조한다. `file` 모드(RP 페이지가 CORS 로 직접 호출)는 지금처럼 `Origin` 헤더를 대조한다. `snap` 모드에서는
    `/wallet/login` 의 CORS 를 닫는다(`loginCors` 는 `file` 모드에서만 붙인다).
  - `POST /wallet/tx/prepare { r_s, to, value, data, disclose }` → `{ walletAddr, calldata, nonce, disclosure, deployNeeded, deployCalldata? }`.
    팩토리 배포가 필요하면 `deployCalldata`(팩토리 `deploy(PPID)`)도 함께 주어 페이지가 트랜잭션 두 개를 순서대로 보낸다.
  - `POST /wallet/tx/record { r_s, txHash }` → 영수증 파싱 결과(기존 `/wallet/tx` 응답 형식). `file` 모드의 기존 `POST /wallet/tx`(릴레이어)는
    그대로 둔다.
  - `GET /wallet/config` → `{ secrets: 'snap'|'file', snapId, walletOrigin, rpcUrl, chainId }`.
- **RP 오리진에 여는 것:** `/authorize` 페이지(GET)와, 비밀이 필요 없는 `/wallet/revalidate`·`/wallet/request`(CORS 유지). `/wallet/login`·`/wallet/register`·`/wallet/tx/*` 는 같은 오리진(지갑 페이지)만. 팝업은 같은 오리진에서 에이전트를 부른다.

### 3.4 RP 페이지 `mode3/rp.html`·`mode3_rp.js`

- "Mode 3 로그인": 챌린지를 받은 뒤 `window.open(`${walletAgentOrigin}/authorize?…`)` 로 팝업을 열고 `message` 이벤트를 기다린다
  (`event.origin === info.walletAgentOrigin`, `event.data.r_s === 요청 r_s`). 결과로 `/api/mode3/login` 을 지금처럼 호출한다 — 즉 **팝업이
  RP 서버에 직접 내지 않고 RP 페이지가 낸다**(현재 흐름 유지: 지갑은 π·σ 를 RP 페이지에 주고, RP 페이지가 자기 서버에 제출).
  따라서 팝업 결과에는 `{ proof, publicSignals, sig, pk_i, r_s, root, cacheHit, timings }` 이 실린다(지금 `/wallet/login` 응답과 같다).
- 재검증·세션 요청: 지금처럼 RP 페이지가 에이전트에 부를 수 없게 되므로(CORS 닫힘) **이 둘도 팝업 없이 되게** 에이전트가 RP 오리진에
  `/wallet/revalidate`·`/wallet/request` 만 CORS 로 계속 연다. 이유: 세션 안 요청은 비밀이 필요 없다(세션키 서명뿐). `needs_consent` 면
  RP 페이지가 팝업을 다시 연다.
- `mode3_rp.js` 는 변경 없음(`rp_info` 의 `walletAgentOrigin` 그대로).

---

## 4. 흐름

### 4.1 등록
```
지갑 페이지 ── Snap.register ──▶ Snap: prompt(uid), prompt(pwd) → s_u,r_u 생성 → cm_u → 상태 저장 → { uid, pwd, cm_u }
지갑 페이지 ── POST /wallet/register { uid, pwd, cm_u } ──▶ 에이전트 ── POST /cia/register ──▶ CIA → { sk_u, attrs }
지갑 페이지 ◀── { uid, sk_u, attrs } ── 에이전트(파일에는 uid·cm_u·attrs 만)
지갑 페이지 ── Snap.storeRegistration { sk_u, attrs } ──▶ Snap
```
비밀번호는 Snap → 페이지 → 에이전트 → CIA 를 한 번 지나고 어디에도 남지 않는다.

### 4.2 로그인(팝업)
```
RP 페이지: 챌린지 r_s ← RP 서버 → window.open(`${walletAgentOrigin}/?authorize=1`) → 'mode3-authorize-ready' 받으면 요청을 postMessage
팝업: event.origin === request.origin 확인 → precheck(인증서·팩토리) → Snap.consentLogin → 증인 → POST /wallet/login { …, witness, verifiedOrigin }
에이전트: 트리 동기화 → (없거나 폐기면) 사용자 자격증명 발급(π_u) → 세션 발급 → π_rp → 세션 저장(+witness 메모리) → 응답
팝업: userCredIssued 면 Snap.updateUserCred; attrsChanged 면 Snap.syncAttrs → opener.postMessage(result, origin) → close
RP 페이지: 결과로 POST /api/mode3/login → 세션
```

### 4.3 재검증·세션 요청·재증명
- `/wallet/revalidate`·`/wallet/request`: RP 페이지가 CORS 로 호출(지금과 같음). 재증명이 필요하면 `sessions[r_s].witness` 를 쓴다.
- 프로세스 재시작 등으로 `witness` 가 없으면 `409 needs_consent` → RP 페이지가 같은 팝업을 열고 `{ type:'mode3-authorize', reauth:true,
  r_s, … }` 를 보낸다. 팝업은 `consentLogin` 을 다시 받아 `POST /wallet/session/witness { r_s, witness }` 로 채운 뒤 결과를 돌려주고,
  RP 페이지가 재검증을 이어 간다.

### 4.4 트랜잭션(MetaMask)
```
지갑 페이지: 폼 → Snap.consentDisclosure(슬롯 목록, to, value) → POST /wallet/tx/prepare → { walletAddr, calldata, deployCalldata? }
지갑 페이지: (deployCalldata 면 먼저) eth_sendTransaction({ from: EOA, to: factory|walletAddr, data }) → MetaMask 확인 창 → txHash
지갑 페이지: POST /wallet/tx/record { r_s, txHash } → 에이전트가 영수증 파싱 → 결과 표시
```
`file` 모드는 기존 `/wallet/tx`(릴레이어)를 그대로 쓴다.

### 4.5 자기 폐기
지갑 페이지 → Snap.selfRevoke(비밀번호 prompt) → `POST /wallet/self_revoke { uid, pwd }` → 에이전트가 `POST /cia/account/self_revoke`
로 중계하고 CIA 응답을 그대로 돌려준다(T6 에서 추가. `cia.js` 에는 CORS 가 없어 브라우저가 :5100 → :4100 을 직접 부를 수 없다 —
Ruling 7). CORS 를 붙이지 않아 같은 오리진(지갑 페이지)만 부른다. 비밀번호는 중계만 하고 로그·상태 파일에 남지 않는다.
Snap `reset` 은 사용자가 따로 누른다.

---

## 5. 오류 처리

- Snap 미설치·연결 거절: 페이지가 "MetaMask 연결" 상태를 표시하고 로그인 팝업은 `{ ok:false, reason:'snap_unavailable' }` 를 RP 에 돌려준다.
- 동의 거절: `{ ok:false, reason:'user_denied' }`. RP 페이지는 그대로 표시.
- 팝업 차단: RP 페이지가 `window.open` 이 `null` 이면 안내 문구.
- `witness` 형식 오류(스칼라 범위, uid 불일치): 에이전트 `400 bad_witness`. 파일의 공개 `uid` 와 증인의 `uid` 가 다르면 거절.
- MetaMask 트랜잭션 거절: 페이지가 `user_rejected` 표시, 에이전트 상태 변화 없음(nonce 는 컨트랙트가 관리하므로 문제 없음).
- `snap` 모드에서 `witness` 없이 `/wallet/login` 호출: `400 witness_required`. `file` 모드에서 `witness` 가 오면 무시(경고 로그).

---

## 6. 보안·프라이버시 메모

- RP 프런트엔드는 여전히 uid·s_u·blind 를 보지 못한다(팝업 결과는 공개 값).
- 에이전트는 등록 비밀을 디스크에 쓰지 않는다. 세션 동안 메모리 보유는 사용자 결정이며 문서에 명시한다. 파일에는 공개 값만 남는다.
- 발신 EOA 노출(§2)은 데모 한계. 릴레이어 없이 EOA 가 가스를 내므로 `Mode3Wallet` 의 `execute` 검사는 그대로(발신자 무관).
- 팝업 `postMessage` 는 대상 오리진 고정 + RP 측 오리진 검사. 요청 파라미터의 `origin` 은 `precheck` 에서 인증서 `cert_s` 의 오리진과
  대조하므로 피싱 페이지가 남의 arid 로 팝업을 열어도 인증서 검증에서 막힌다(지금과 같은 방어).
- Snap `origin` 검사로 다른 dapp 이 증인을 요청할 수 없다.

---

## 7. 테스트

- `file` 모드: 기존 `chain` 그룹(지갑 에이전트·e2e·데모 스택)을 그대로 통과시킨다(`SecretSource=file` 이 지금 동작과 같다). `/wallet/login`
  CORS 제거로 깨지는 테스트는 `/authorize` 팝업 대신 **같은 오리진 호출**로 바꾼다(테스트 헬퍼는 이미 서버 간 fetch 라 CORS 영향 없음).
- `snap` 모드(Snap 시뮬레이터): `tests/helpers/snap_sim.mjs` 가 Snap 상태와 RPC 를 흉내 낸다(`register`/`consentLogin` 등을 함수로).
  `tests/test_mode3_wallet_snap.mjs`: 등록(응답에 sk_u, 파일에 비밀 없음), 로그인(증인 첨부 성공, 미첨부 400, uid 불일치 400), 재검증(메모리
  witness 사용), 재시작 후 `needs_consent`, `/wallet/tx/prepare`·`/wallet/tx/record`(hardhat 계정이 EOA 역할로 calldata 전송), 상태 파일에
  s_u·sk_u·blind_u 가 없음을 grep 으로 확인.
- 브라우저 경로(팝업·postMessage·MetaMask): Playwright 로 지갑 페이지·RP 페이지를 띄우고 `window.ethereum` 을 **스텁**(eth_requestAccounts,
  wallet_requestSnaps, wallet_invokeSnap → 시뮬레이터, eth_sendTransaction → hardhat 계정으로 실제 전송)해 로그인·공개·트랜잭션 시나리오를
  돌린다(`tests/test_mode3_browser.mjs`, `run_tests.sh` 의 `chain` 그룹). Playwright 는 이미 의존성에 있는지 T1 에서 확인, 없으면 추가는
  사용자 승인.
- 실제 MetaMask Flask: `docs/MODE3_DEMO.md` 에 수동 체크리스트(Flask 설치, `snap-mode3` 빌드·serve, 연결, 등록, 로그인, 공개 트랜잭션).

---

## 8. 구현 범위와 순서(계획 문서의 뼈대)

1. `lib/mode3_secret_source.js` + 에이전트 `file` 모드 리팩터(동작 불변, 기존 테스트 통과).
2. 에이전트 `snap` 모드: `witness` 첨부 로그인, 메모리 세션 증인, `needs_consent`, `/wallet/register` 변경, `/wallet/authorize/precheck`,
   `/wallet/tx/prepare`·`/wallet/tx/record`, `/wallet/config`, CORS 정리. 시뮬레이터 테스트.
3. `snap-mode3/` 패키지: manifest·빌드·RPC 8개·대화상자·상태. 단위 테스트는 `onRpcRequest` 를 Node 에서 직접 호출(Snap 전역 `snap.request`
   를 스텁).
4. 지갑 페이지: MetaMask 연결, 등록·트랜잭션 폼의 Snap 경로, `/authorize` 팝업 화면.
5. RP 페이지: 팝업 열기·`postMessage`·`needs_consent` 재팝업. 브라우저 테스트(Playwright).
6. 문서(`docs/MODE3_DEMO.md` Snap 절·Flask 체크리스트), 슬라이드 후속 4번 갱신.

---

## 9. 결정된 것 / 열린 것

- 결정(2026-09-22, 사용자): ①~④(머리말). 등록 uid·비밀번호 입력은 Snap 대화상자.

### 열린 것 → 닫힌 결과 (2026-09-22 구현)

- **(a) 세션 증인의 TTL — 기본값대로 닫았다.** `sessions[r_s].witness` 는 세션 엔트리와 수명을 같이한다(세션 만료 `max_height`,
  폐기·속성 변경으로 세션을 버릴 때, 그리고 프로세스 재시작). `persist()` 가 `witness` 를 빼고 쓰므로 재시작 뒤에는 `409 needs_consent`
  가 나고 RP 페이지가 팝업을 다시 연다(§4.3).
- **(b) Playwright — 추가했다(사용자 승인).** 루트 devDependency `@playwright/test`. 단 번들 chromium 을 내려받지 않고 **설치된
  Google Chrome**(`channel: 'chrome'`)을 쓴다. 이 의존성이 필요한 테스트는 `run_tests.sh` 의 별도 `browser` 그룹이다(Ruling 8).
- **(c) Snap 번들의 circomlibjs — 쓰지 않는다.** `circomlibjs.buildBabyjub` 은 ffjavascript 의 WASM 곡선을 올리는데 이 Snap 의
  manifest 에는 `endowment:webassembly` 가 없어야 해서 런타임에 죽는다(실측: `WebAssembly` 를 지우면 `buildBabyjub` 이
  `Cannot read properties of undefined (reading 'Memory')`). 그래서 Baby Jubjub 덧셈·스칼라곱을 BigInt 로 `snap-mode3/src/crypto.js` 에
  직접 적고, 결과 `cm_u` 가 루트 `lib/mode3_issuance.js` 의 `registrationCommit`(circomlibjs 사용)과 **같은 점**인지 단위 테스트로
  고정했다. §3.1 의 "circomlibjs 로 계산한다" 는 이 결정으로 대체된다(계산 위치는 그대로 Snap 안이다 — §3.1 의 대안은 쓰지 않았다).

### 실행 중 내린 판정(Ruling)

- **Ruling 1** — `/wallet/config` 는 T1 에서 만들고 RP 오리진 CORS(GET)를 처음부터 붙인다. RP 페이지가 지갑의 비밀 모드를 알아야
  로그인 경로(직접 호출 / 팝업)를 고르기 때문이고, 이 응답에는 비밀이 없다. (T6 에서 `ciaUrl` 은 뺐다 — Ruling 7 로 필요가 없어졌고
  RP 오리진에도 나가던 값이다.)
- **Ruling 2** — 새 의존성은 사용자 승인이 필요하다(CLAUDE.md). `snap-mode3` 의 `@metamask/snaps-sdk`·`@metamask/snaps-cli` 와 루트
  devDep `@playwright/test` 를 승인받았다(`circomlibjs` 는 (c) 대로 결국 쓰지 않았다).
- **Ruling 3** — `chain`·`browser` 테스트용 hardhat 노드(:8545)는 이 작업 세션이 띄우고 끝에 내린다(CLAUDE.md 2026-09-11 허용).
- **Ruling 4** — 세션 경로(`/wallet/revalidate`·`/wallet/request`·`/wallet/tx/*`)는 **본문 `witness` 를 무시하고 메모리 증인만** 쓴다.
  본문 증인을 받는 곳은 `/wallet/login`·`/wallet/session/witness`·`/wallet/attrs/sync` 뿐이다 — 세션 경로는 RP 오리진에 열려 있으므로,
  거기서 증인을 받으면 Snap 동의를 우회하는 입력 경로가 생긴다.
- **Ruling 5** — 브라우저 테스트의 `wallet_invokeSnap` 스텁은 시뮬레이터가 아니라 **`snap-mode3/src/index.js` 의 진짜 `onRpcRequest`**
  를 주입해 돌린다(import 만 치환하고, 치환 정규식이 안 맞으면 throw 해서 드리프트가 조용히 넘어가지 않는다).
- **Ruling 6** — Snap `updateUserCred` 는 인자 없음(`params` 부재)을 `bad_params` 로 막고, **명시적 `null`** 만 폐기로 본다. 페이지의
  실수로 보관 중인 사용자 자격증명이 지워지지 않게 한다.
- **Ruling 7** — 자기 폐기는 `cia.js` 에 CORS 를 여는 대신 **에이전트 프록시**(`POST /wallet/self_revoke`)로 푼다. CIA 서버는 이
  작업에서 바꾸지 않는다는 계획을 지키고, 에이전트는 이미 `ciaPost` 로 CIA 와 통신한다. §3.2·§4.5 참고.
- **Ruling 8** — 브라우저 테스트는 `chain` 이 아니라 새 **`browser` 그룹**이다. `chain` 의 계약("hardhat :8545 만 있으면 된다")을
  지키기 위해서다. `all` 에는 포함하되, Chrome/Chromium 이 없는 머신에서는 그 한 줄 때문에 `all` 이 실패한다는 주석을 남겼다.
- **Ruling 9** — `snap-mode3/test/rpc.test.mjs` 도 `run_tests.sh` 에 **`snap` 그룹**으로 등록한다(패키지 지역 테스트라는 이유로
  어느 그룹에도 없으면 아무도 돌리지 않는다 — CLAUDE.md). `snap-mode3/node_modules` 를 전제하므로 `unit` 의 "외부 의존 없음"
  계약은 건드리지 않고, `browser` 와 같은 방식으로 `all` 에 포함하되 install 이 안 된 머신에서는 그 줄 때문에 `all` 이
  실패한다는 주석을 남긴다. 같은 라운드에서 프록시가 등록된 `uid` 만 중계하도록 403 검사를 더했다(리뷰 Minor 3).
