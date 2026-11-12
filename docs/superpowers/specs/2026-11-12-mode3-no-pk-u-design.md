# Mode 3 — 등록 키(sk_u·pk_u) 제거: 사용자 요청 인증을 π_IdP(ctx·tag)로 (설계, 2026-11-12)

- 상태: 사용자 승인(2026-11-12, 대화 중 "pk_u는 없애도 될 것 같고 없애야 할 것 같고" → 안 선택 "B안으로 가고" → 2부 "추천대로"). 미구현.
- 배경: IdP 는 등록 때 사용자 키 pk_u 를 받아 두고, 발급·슬롯 조회·세션 폐기 요청을 sk_u 서명(`sig_u`)으로 인증한다. 기존 web2 IdP 는 사용자 키를 등록받지 않는다(사용자 지적).
  pk_u 는 IdP 쪽 연결 고리이기도 하다(리뷰 I-3 — 같은 pk_u 면 다른 계정이 한 사람으로 묶인다; 스냅 0.3.0 이 계정 번호로 갈랐다).
  한편 지갑은 이미 세션마다 "auid 의 s_u 를 안다" 는 π_IdP 를 낸다 — 같은 증명에 요청을 묶으면 sk_u 가 할 일이 없다.
  sk_u 를 없애도 보호 수준은 같다: 스냅은 s_u 와 sk_u 를 **함께** 에이전트에 넘긴다(`snap-mode3/src/index.js` buildWitness) — 둘 중 하나만 새는 경로가 없다.
- 비범위: `pi_cred` 회로·`PiCredVerifier.sol`·컨트랙트·RP(`mode3_rp.js`, pk_u 를 쓰지 않는다), 세션키 서명 `sig_i`, 관리자 폐기 경로, 계정 비밀번호 경로(`/cia/account/self_revoke`·`/cia/user/unlink_wallet`),
  PPID 식·auid 식·s_u 유도(바꾸지 않는다 — 기존 auid·PPID 가 그대로다), Mode 1·Mode 2.

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| P1 | sk_u·pk_u·`sig_u`·`sig_reg` 를 **전부 없앤다**. 사용자 요청 넷(등록·발급·슬롯 조회·세션 폐기)은 π_IdP 로 인증한다. | 사용자 선택. IdP 가 사용자 키를 갖지 않는다. 대가: 등록·슬롯 조회·세션 폐기가 서명 대신 증명을 만든다(§7). |
| P2 | π_IdP 에 공개 입력 둘을 더한다(B안): `ctx`(요청 용도·내용의 해시, 회로 밖에서 계산)와 `tag = Poseidon(T_TAG, s_u, ctx)`(회로 안에서 검사). | 사용자 선택 B. `ctx` 가 증명을 그 요청에 묶고, `tag` 는 증명을 만들기 **전에** 계산할 수 있어 Google nonce 에 넣는다(§3.3). |
| P3 | "등록됨" 의 기준은 **auid 가 있음**. | pk_u 가 하던 표지 역할을 auid 가 한다 — 등록된 계정에는 늘 둘 다 있었다(`lib/mode3_cia_state.js`). |
| P4 | 발급이 아닌 요청(등록·슬롯·세션 폐기)은 π_IdP 의 세션 부분(C_u·auid_s·C_s·max_height)을 **버릴 값**으로 채운다. 회로는 하나다. | 회로·키를 하나로 둔다(빌드·배포·검증 경로 하나). 대가: 그 요청들이 6천여 제약 증명을 만든다. |
| P5 | 옛 요청 형식과 **호환을 두지 않는다**. IdP·에이전트·스냅·웹 사용자 페이지를 한 번에 바꾼다. | 데모다. 두 형식을 함께 받으면 pk_u 를 지울 수 없다. |
| P6 | 웹 사용자 페이지(`mode3/user`, 2026-10-22 개발 중지)도 프로토콜 부분만 같이 고친다. | 사용자 선택(대안 "테스트 그룹에서 빼고 둔다" 기각). 같은 `lib/mode3_wallet.js`·IdP 경로를 써서, 두면 페이지와 테스트가 깨진다. |
| P7 | 회로는 `pi_idp` 만 다시 빌드한다. | `pi_cred` 를 다시 빌드하면 zkey 가 바뀌어 배포된 온체인 검증자와 어긋난다. |

## 2. 회로 (`circuits/pi_idp.circom`)

- 공개 입력 8 → 10. **기존 순서는 그대로** 두고 뒤에 붙인다:
  `[0] uid [1] auid [2] auid_s [3] C_u_x [4] C_u_y [5] C_s_x [6] C_s_y [7] max_height [8] ctx [9] tag`.
- 새 제약 하나: `tag === Poseidon(DOMAIN_MODE3_TAG, s_u, ctx)`. `ctx` 는 공개 입력으로만 들어온다(회로는 그 내용을 모른다).
- `DOMAIN_MODE3_TAG` = ASCII `"MODE3TAG"` 를 큰 끝(big-endian) 정수로 읽은 값(기존 `DOMAIN_MODE3_AUID` 와 같은 규칙). `lib/mode3_credential.js` 에 같은 상수를 둔다.
- 늘어나는 제약은 Poseidon(3) 하나 — 약 240개로 **추정**(빌드 뒤 `.r1cs` 로 확인해 결과 문서에 적는다). 지금 6,325.
- `lib/mode3_idp_proof.js`: `IDP_PUB_INDEX` 에 `CTX: 8, TAG: 9, COUNT: 10`. `idpPublicSignals`·`proveIdp` 가 `ctx`·`tag` 를 받는다. `tests/test_mode3_artifacts.mjs` 의 `.sym` 대조가 새 순서를 본다.
- 빌드: `scripts/build_mode3_circuit.sh` 가 회로 이름을 인자로 받게 한다(`bash scripts/build_mode3_circuit.sh pi_idp`). 인자가 없으면 지금처럼 둘 다. **이 작업에서는 `pi_idp` 만 빌드한다**(P7). 빌드는 실행 전에 사용자 승인을 받는다(CLAUDE.md).
  산출물은 `build/mode3/pi_idp_final.zkey`·`pi_idp_vkey.json`·`pi_idp_js/pi_idp.wasm` — 에이전트·IdP·웹 사용자 페이지(`mode3_user_static.js`)가 모두 이 자리에서 읽는다(사본 없음).

## 3. 요청 인증

### 3.1 ctx (회로 밖, `lib/mode3_credential.js`)

| 요청 | ctx | 지금의 서명 메시지 |
|---|---|---|
| 발급 `/cia/issue` | `Poseidon(D_CTX_ISSUE, arid_s, chainid, allowAgent)` | `(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height)` — 나머지 넷은 π_IdP 공개 입력이 이미 덮는다 |
| 등록 `/cia/register` | `Poseidon(D_CTX_REG, n)` — n 은 지갑이 뽑은 난수(2^250 미만) | `(uid, auid)` — 둘 다 공개 입력 |
| 슬롯 조회 `/cia/slot` | `Poseidon(D_CTX_SLOT, nonce)` | `(uid, nonce)` |
| 세션 폐기 `/cia/revoke` scope=session | `Poseidon(D_CTX_REVOKE, Cf_s, bound, nonce)` | `(uid, Cf_s, bound, nonce)` |

- 도메인 상수 넷은 ASCII `"MODE3CTXISSUE"`·`"MODE3CTXREG"`·`"MODE3CTXSLOT"`·`"MODE3CTXREVOKE"` 의 큰 끝 정수. 용도가 다르면 ctx 가 달라, 한 요청의 증명을 다른 요청에 쓰지 못한다.
- nonce 의 신선도는 지금과 같다(IdP 는 슬롯 조회·세션 폐기 nonce 를 기억하지 않는다 — 다시 보내도 같은 답·같은 결과다).

### 3.2 IdP 의 검증 (`cia.js`)

네 경로가 같은 순서로 본다.
1. 계정을 찾고 **등록됨(auid 있음)** 을 본다(등록 경로는 요청의 `auid`).
2. `ctx` 를 요청 필드에서 **스스로 계산**한다. 지갑이 보낸 ctx 는 받지 않는다.
3. 공개 입력을 스스로 조립한다: `uid`(요청·계정), `auid`(DB 값 — 등록 경로만 요청 값), 요청의 `auid_s`·`C_u_pt`·`C_s_pt`·`max_height`·`tag`, 계산한 `ctx`.
4. `verifyIdp` 가 실패하면 400 `bad_idp_proof`. 지금의 `bad user signature` 응답은 없어진다.

- 발급: 지금도 π_IdP 를 하나 검증한다 — `sig_u` 검증이 빠지고 공개 입력이 둘 는다. 요청에서 `sig_u` 가 빠지고 `tag` 가 든다.
- 등록·슬롯·세션 폐기: 요청에 `{ auid_s, C_u_pt, C_s_pt, max_height, tag, proof_idp }` 가 든다(P4 의 버릴 값). IdP 는 검증에만 쓰고 **저장하지 않는다**(`lastAuidS` 도 건드리지 않는다).
  지갑은 버릴 값을 `attrs = 0`, `arid = 0`, `pk_i = 0`, `max_height = 0`, `blind_u`·`r_rp`·`r_s` = 새 난수로 만든다 — C_u 에 실제 s_u 가 들어가므로 blind 는 꼭 난수다.
- 등록: 요청은 `{ uid|id_token, (pwd|code), auid, n, …위 여섯 }`. `pk_u`·`sig_reg` 는 없다.
  복구(스펙 snap-derived-secrets S3): 이미 등록된 계정에 **같은 auid + 유효한 증명**이 오면 슬롯을 새로 잡지 않고 기존 등록을 돌려준다. auid 가 다르면 409 `already registered`.
- 발급의 암묵 등록(Google, `registration` 동봉): `registration` 은 `{ auid }` 뿐이다. 발급 증명 하나를 `auid = registration.auid` 로 검증하고(등록용 증명을 따로 받지 않는다), nonce 를 확인한 **뒤에** 등록·발급한다.

### 3.3 Google nonce (`lib/mode3_oidc_nonce.js`)

- `regNonce(tag) = "reg:" + SHA-256(tag 10진)`, `issueNonce(tag) = "issue:" + SHA-256(tag 10진)`. pk_u 를 받던 인자는 없어진다.
- IdP 는 증명을 검증한 뒤 토큰의 nonce 가 그 `tag` 의 해시와 같은지 본다. `tag` 는 s_u 없이 못 만들고 회로가 auid 와 **같은 s_u** 를 강제하므로, 가로챈 토큰으로 다른 auid 를 등록·발급하지 못한다(pk_u 에 묶던 것과 같은 성질, 리뷰 C1 의 순서 요건 유지).
- 등록의 n: 토큰을 받기 전에 뽑아 `tag` 를 계산하고, 같은 n 을 등록 요청에 싣는다. uid 는 토큰을 받은 뒤에야 알지만 `tag` 에는 uid 가 들어가지 않는다.

## 4. 지갑 쪽

### 4.1 스냅 (`snap-mode3`, 0.3.1 → 0.4.0)
- `src/crypto.js`: sk_u 유도(`ENTROPY_SALT_SK_U`·`skFromEntropy`)를 지운다. **s_u 유도 salt(`zkd/mode3/s_u/v2/<k>`)는 그대로** — 같은 시드·같은 번호면 같은 s_u·auid·PPID.
- `register`·`prepareRegister` 는 `{ (uid,) s_u, index }` 만 돌려준다. 등록 기록에 `sk_u` 를 넣지 않는다. 증인(`buildWitness`)에서도 뺀다.
- 옛 상태(0.3.x)의 `registration.sk_u` 는 읽을 때 무시하고 다음 저장 때 사라진다. 등록 검사에서 `sk_u` 형식 조건을 뺀다 — 0.3.x 등록은 다시 등록하지 않고 그대로 쓴다.
- `getStoredState` 에 sk_u 가 없다 → zk 스냅 화면(http://localhost:5100) "내 계정" 탭의 sk_u 줄과 문자열 `wallet_me_f_sk_u` 를 지운다. 초기화 확인 문구 "등록 비밀(s_u·sk_u)" → "등록 비밀(s_u)".

### 4.2 라이브러리 (`lib/mode3_wallet.js`·`lib/mode3_secret_source.js`)
- 지운다: `eddsaPubOf`, `signRegistration`, `signSlotRequest`, `signRevokeSession`, `signIssueRequest`, 그 메시지 함수들, `createRegistration` 의 `sk_u`·`pk_u`, `registrationSecretsFromSeed` 의 `sk_u`.
- 더한다: `buildAuthProof({ uid, s_u, ctx })` — 버릴 값으로 π_IdP 를 만들어 `{ auid_s, C_u_pt, C_s_pt, max_height, tag, proof_idp }` 를 돌려준다(등록·슬롯·세션 폐기가 함께 쓴다). `tagOf({ s_u, ctx })`, `ctx` 넷의 계산 함수.
- `buildIssueRequest`: `sk_u` 인자가 없어지고 본문에 `sig_u` 대신 `tag` 가 든다.
- `mode3_secret_source.js`: 증인·등록 모양에서 `sk_u`·`pk_u` 를 뺀다.

### 4.3 에이전트 (`mode3_wallet_agent.js`)
- `/wallet/register`·`/wallet/register/resume`: 본문에서 `sk_u` 를 받지 않는다(`s_u` 만). resume 의 대조는 auid 하나.
- `/wallet/oidc/nonce`: `purpose: 'register'` 는 `{ s_u }` 를 받아 n 을 뽑고 `{ nonce, n }` 을 돌려준다(페이지가 n 을 `/wallet/register` 에 다시 싣는다). `purpose: 'issue'` 는 세션 증인의 s_u 로 `tag` 를 계산한다 — 등록 기록의 `pk_u` 를 보던 조건은 `auid` 로.
- 슬롯 조회·세션 폐기: `buildAuthProof` 로 증명을 만들어 낸다. snap 모드는 세션 증인의 `s_u`(지금 `sk_u` 를 꺼내던 자리), 증인이 없으면 지금처럼 409 `needs_consent`.
- 상태 파일의 `registration.pk_u`·(file 모드의) `sk_u` 는 읽을 때 버린다.

### 4.4 화면
- zk 스냅 화면(`mode3/wallet.html`): 등록·resume·Google 등록 호출에서 `sk_u` 를 빼고 n 을 나른다. 비밀 가림 목록에서 `sk_u` 를 뺀다.
- 속성 도구(`mode3/attr.html`)·IdP 관리자 페이지(`mode3/cia_admin.html`): 바뀌는 동작 없음(주석의 sk_u·pk_u 언급만 정리).

### 4.5 웹 사용자 페이지 (`mode3/user/core/user_core.js`, P6)
- 같은 라이브러리 함수로 옮긴다: 등록·슬롯 조회·세션 폐기는 `buildAuthProof`, 발급은 새 `buildIssueRequest`, nonce 는 `regNonce(tag)`·`issueNonce(tag)`. 금고에 `sk_u`·`pk_u` 를 넣지 않는다(옛 금고의 값은 읽을 때 무시).
- 복구 코드: `zkd1`(시드)은 그대로 — 시드에서 s_u 만 유도한다. `zkd0`(s_u 32B ‖ sk_u 32B)은 **형식을 유지**하되 읽을 때 뒤 32바이트를 무시하고, 쓸 때 0 으로 채운다. 새 형식은 만들지 않는다.
- `mode3/user/dist/` 는 `npm run user:build` 산출물(git 제외)이라 다시 만든다.
- 화면·문구는 고치지 않는다(개발 중지 상태 유지).

## 5. IdP 상태 (`lib/mode3_cia_state.js`, 버전 12 → 13)

- 계정 기록에서 `pk_u` 가 없어진다. 등록 전 = `auid:null`·`slot:null`, 등록됨 = `auid`(10진)·`slot`(정수).
- 로더는 **12 와 13 을 받는다**. 12 면 계정마다 `pk_u` 를 지우고 버전을 13 으로 올려 쓴다(다음 저장 때 파일에 반영). auid 는 그대로라 기존 계정은 재등록 없이 이어진다. 13 인데 `pk_u` 가 남아 있으면(손으로 고친 파일) 같은 식으로 지운다 — 거부하지 않는다.
- 되돌리기: 옛 코드는 13 파일을 "unsupported version" 으로 거부한다. 옛 코드로 돌아가려면 반영 전에 떠 둔 상태 파일 사본이 필요하다 — 배포 절차(§6)에 사본 뜨기를 넣는다. 상태 파일을 지우지는 않는다.
- `cia.js` 의 `a.pk_u` 판정(15곳쯤: `/cia/accounts`·`/cia/me` 의 `registered`, 404·409 가드, 연결 해제, 계정 폐기)을 `a.auid` 로 바꾼다. `newAccountRecord` 에서 `pk_u` 를 뺀다.

## 6. 배포 순서

1. 로컬: `pi_idp` 빌드(승인 뒤) → 테스트 전체.
2. IdP VM(.10)의 상태 파일 사본을 뜬다.
3. 한 번에 교체: VM 에 rsync(코드 + `build/mode3/pi_idp_*`) → IdP 재시작 → 로컬 에이전트 재시작 → 스냅 0.4.0 재설치(제거 후 다시 연결). RP VM(.11/.12)은 코드가 안 바뀌지만 같은 트리를 받는다.
4. 데모 리셋. pk_u 제거만으로는 필요 없지만(auid 가 그대로), 아직 배포 안 된 스냅 0.3.0(계정 번호 유도)이 배포본의 s_u 를 바꾸므로 함께 한다.
- 이 배포에 같이 실리는 미배포 커밋: 스냅 0.3.0·0.3.1("내 계정" 탭), 최신 auid_s, 속성 도구 백업 불러오기 수정.

## 7. 비용·한계

- 발급: 증명 수는 그대로 하나. 제약이 약 240개(추정) 는다 — 지금 prove ≈292 ms·verify ≈13 ms(`results/mode3_v11_figure_protocol_20261013.md`). 빌드 뒤 같은 머신에서 다시 재서 **새 결과 파일**에 적는다(기존 파일은 덮어쓰지 않는다).
- 등록·슬롯 조회·세션 폐기: 요청마다 증명 하나(≈0.3초)가 든다. IdP 는 EdDSA 검증 대신 Groth16 검증(≈13 ms)을 한다 — 인증 전 요청의 검증 비용이 는다(데모 범위에서는 받아들인다).
- 계정의 비밀은 s_u 하나다. s_u 가 새면 계정 전체가 넘어간다 — 지금도 s_u·sk_u 가 함께 움직여 실질은 같다.
- 스냅 번호 찾기(스펙 snap-account-index K2): "후보 pk_u 를 IdP 에 대 보지 않는다" 의 근거는 auid 에도 그대로 선다(번호가 다르면 auid 가 다르다) — 결정은 유지.

## 8. 테스트

- 단위: `lib/mode3_idp_proof.js`(공개 입력 10개·순서), ctx 넷의 도메인 분리(용도가 다르면 다른 값), `tagOf`, nonce 함수, 상태 로더(12 → 13 이행, 13 에 남은 pk_u 는 지움, 등록됨인데 slot 이 없으면 거부).
- IdP(chain 그룹): 네 경로 각각 — 맞는 증명은 통과, **다른 용도의 ctx 로 만든 증명은 `bad_idp_proof`**, 요청 필드(예: `allowAgent`·`bound`)를 바꾸면 `bad_idp_proof`, 다른 s_u 의 증명은 `bad_idp_proof`. 등록 복구(같은 auid → 기존 슬롯, 다른 auid → 409). Google: tag 가 다른 토큰은 `oidc_nonce_mismatch`.
- 스냅: `register`·`prepareRegister`·`getStoredState`·`buildWitness` 에 sk_u 가 없다, 0.3.x 상태(sk_u 있음)를 그대로 읽는다.
- 브라우저: 등록 → 로그인 → 세션 폐기 → 슬롯 조회가 snap 모드에서 그대로 돈다, "내 계정" 탭에 sk_u 줄이 없다. 웹 사용자 페이지 두 파일.
- 계약(contract) 그룹은 바뀌지 않는다(`pi_cred` 그대로) — 한 번 돌려 확인만 한다.
- sk_u·pk_u·`sig_u`·`sig_reg` 를 쓰는 테스트·도우미 파일 30여 개를 새 형식으로 옮긴다(`tests/helpers/mode3_flow.mjs`·`isolated_cia.mjs`·`snap_sim.mjs` 가 중심).

## 9. 문서

- 런북 `docs/MODE3_DEMO.md`(스냅 0.4.0, 재설치, 리셋), V11 스펙 `2026-10-12-mode3-v11-figure-protocol-design.md` 의 `sig_u`·pk_u 서술에 이 스펙으로 대체됐다는 표시,
  `2026-11-12-mode3-snap-derived-secrets-design.md`·`2026-11-12-mode3-snap-account-index-design.md` 의 sk_u 서술에 같은 표시, `cia.js` 머리 주석의 계정 모양.
