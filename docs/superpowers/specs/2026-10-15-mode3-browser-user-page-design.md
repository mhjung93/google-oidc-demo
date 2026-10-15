# Mode 3 — 설치 없는 브라우저 사용자 페이지 + RP 릴레이

작성 2026-10-15. 상태: **승인(2026-10-15) — 구현 계획 docs/superpowers/plans/2026-10-15-mode3-browser-user-page.md 의 "스펙 대비 결정" R1~R12 가 우선한다**. 브랜치 `feat/mode3-v11`(V11 그림 프로토콜 `2026-10-12-mode3-v11-figure-protocol-design.md` 위). 근거: 2026-10-15 사용자 요청 "스냅 설치도, 별도 사용자 프로그램도 없이 웹 브라우저에서 그냥 돌게" 와 네 가지 결정(§1).

## 0. 한 줄 요약

사용자 쪽(비밀 보관·Poseidon/EdDSA·π_IdP·π_RP 생성·체인 동기화·트랜잭션 조립)을 **정적 웹앱** `mode3/user/` 로 옮기고, 비밀은 IndexedDB 에 비밀번호로 암호화해 두며, 가스는 RP 가 새 `POST /api/mode3/relay` 로 대납한다. RP 와 사용자 페이지는 팝업·postMessage 로만 대화한다. Node 사용자 에이전트(`mode3_wallet_agent.js`)는 file/snap 모드와 자동 테스트용으로 그대로 둔다. 프로토콜(회로·토큰·컨트랙트·IdP 라우트)은 바뀌지 않는다.

## 1. 결정

- **D1 비밀 보관 = IndexedDB + 비밀번호 암호화.** `s_u·sk_u·blind_u·세션 개인키` 는 PBKDF2(SHA-256, 310,000회, 16바이트 salt) 로 만든 AES-GCM-256 키로 암호화해 저장한다. 나머지(uid·auid·pk_u·슬롯·profile·attrs·userCred 공개 부분·세션 공개 정보·tx 기록·트리 캐시)는 평문. 페이지를 열면 비밀번호로 "잠금 해제" 하고 키는 메모리(탭 수명)에만 둔다. Snap 대비 보안 하향(XSS·사이트 데이터 삭제)은 데모 한계로 §9 에 적는다.
- **D2 릴레이 = RP 후원.** RP 에 `POST /api/mode3/relay` 를 둔다. RP 의 릴레이어 계정(`MODE3_RELAYER_INDEX`, 지금도 팩토리·AttrGate 배포에 쓴다)이 `execute` 트랜잭션을 대신 보낸다. RP 가 전송을 거부할 수 있음(검열)은 한계로 적는다.
- **D3 호스팅 = 작은 정적 서버 :5100 + COOP/COEP.** `mode3_user_static.js` 가 `mode3/user/`(앱)와 `/zk/*`(`build/mode3` 의 zkey·wasm·vkey)를 `Cross-Origin-Opener-Policy: same-origin`·`Cross-Origin-Embedder-Policy: require-corp` 헤더와 함께 낸다 → snarkjs 멀티스레드 wasm. 오리진은 지금 에이전트와 같은 `http://127.0.0.1:5100` 이라 RP·IdP 의 오리진 설정은 그대로다.
- **D4 병행.** Node 에이전트·그 테스트는 유지한다. `lib/mode3_*.js` 를 두 쪽이 공유하고, 브라우저 쪽은 Node 전용 부분만 교체한다(§6). 데모의 기본은 브라우저 페이지(`MODE3_USER_MODE=web`, 런북 §10).
- **D5 번들러 = esbuild(개발 의존성, 사용자 승인 2026-10-15).** 산출물 `mode3/user/dist/*.js` 는 생성물로 두고(`.gitignore`), 빌드 명령은 `npm run user:build`.
- **D6 RP↔사용자 통신 = 팝업·postMessage 만.** 지금 로그인에 쓰는 `?authorize=1` 팝업 경로를 재검증·세션 요청·precheck·config 까지 넓힌다. RP 페이지가 사용자 오리진에 fetch 하는 코드는 web 모드에서 사라진다.

## 2. 구성요소

| 구성요소 | 위치 | 역할 |
|---|---|---|
| 사용자 페이지 | `mode3/user/index.html`, `mode3/user/user.js`(ESM 소스), `mode3/user/worker.js`(증명 워커), `mode3/user/dist/`(esbuild 산출) | 등록·속성·로그인 팝업·재검증·트랜잭션·Selective disclosure proof·세션 폐기·자기 폐기·시연 스위치. 체험 모드·문구는 `mode3/common/strings.js`·`demo.js` 를 그대로 쓴다(`data-page="wallet"` 유지 — 단계·칩이 바뀌지 않는다). |
| 정적 서버 | `mode3_user_static.js` | :5100, COOP/COEP, `/` → `mode3/user/`, `/common/*` → `mode3/common/`, `/zk/*` → `build/mode3/`(읽기 전용). 비밀·상태를 **전혀** 다루지 않는다. |
| 브라우저 라이브러리 | `lib/mode3_*.js`(공유) + `lib/browser/` shim | §6 |
| RP 릴레이 | `mode3_rp.js` `POST /api/mode3/relay`, `GET /api/mode3/relay/:txHash` | §5 |
| IdP CORS | `cia.js` | 사용자 오리진에서 부르는 라우트에 CORS 허용(§5.4) |

Node 에이전트가 하던 역할의 대응: `/wallet/register` → 페이지 함수 `register()`; `/wallet/login` → 팝업 `mode3-authorize`; `/wallet/revalidate`·`/wallet/request`·`/wallet/authorize/precheck`·`/wallet/config` → 팝업 메시지(§4.2); `/wallet/tx`·`/wallet/tx/prepare`·`/wallet/tx/record` → 페이지 `sendTx()` + RP 릴레이; `/wallet/profile` → 페이지 `saveProfile()`; `/wallet/session/revoke`·`/wallet/self_revoke` → 페이지 함수(IdP 직접 호출); `/wallet/status`·`/mode3/health` → 페이지 내부 상태(체험 모드의 `D.stack` 폴링은 web 모드에서 **페이지 자신의 상태**를 쓴다 — `rpCount`·`sessions`·`registered` 를 같은 이름으로 제공).

## 3. 상태 — IndexedDB `mode3-user` (버전 1)

객체 저장소 하나 `kv`(키 → 값), 키:
- `meta`: `{ version: 1, createdAt, kdf: { salt(hex), iterations: 310000 }, check: AES-GCM(key, 'mode3-user') }` — `check` 로 비밀번호 검증.
- `registration`: `{ uid, auid, pk_u:{x,y}, slot, profile, attrs:[6 10진], userCred: { C_u_pt, Cf_u, issuedAt } | null }` (평문; blind_u 는 `secrets`).
- `secrets`: AES-GCM 으로 암호화한 JSON `{ s_u, sk_u, blind_u, sessionKeys: { r_s → sessionPrivKey(hex) } }` + iv.
- `sessions`: `r_s → { arid, origin, PPID, account, pk_trace, factoryAddress, attrGateAddress, allowAgent, r_rp, auid_s, arid_s, credential(토큰 묶음), max_height, chainid, issuedAt, proofCache: { root, regRoot, disclosureKey, proof, publicSignals } | null }` — V11 에이전트의 `state.sessions` 와 같은 모양(auid_s·arid_s·r_rp 는 지금도 지갑 쪽에만 있다, D1).
- `txs`: 배열(에이전트 `txs` 와 같은 항목).
- `rcl`: 동기화 체크포인트 `{ chainId, logAddress, lastBlock, tree, registry }`(에이전트 `mode3_wallet_rcl.json` 과 같은 내용).
- `demo`: 시연 덮어쓰기 `{ scope, ... } | null`(에이전트 `demoOverride` 와 같음).

잠금 모델: `unlock(password)` 가 `meta.check` 를 풀어 키를 메모리에 둔다. 비밀이 필요한 동작(등록·로그인·재검증 재증명·트랜잭션·세션 폐기·자기 폐기)은 잠겨 있으면 `locked` 를 내고 페이지가 비밀번호 창을 띄운다. "잠그기" 버튼과 탭 종료로 키가 사라진다. 비밀번호 변경은 `secrets` 재암호화. 비밀번호 분실 = 복구 불가(데모 한계, 재등록 불가 — IdP 의 uid 가 남으므로 재시연 세트 필요).

## 4. 흐름

### 4.1 페이지 안에서 끝나는 동작
- **등록**: 비밀번호 설정 → `createRegistration(uid)`(브라우저 난수) → `auidOf` → `signRegistration` → `POST {IdP}/cia/register` → 성공 시 `registration`·`secrets` 저장. profile 은 폼 값(비면 `DEFAULT_PROFILE`), 인코딩은 `encodeProfile`(IdP 스키마 `GET /cia/attr_schema`).
- **속성 변경**: `saveProfile()` — 에이전트 `PUT /wallet/profile` 과 같은 규칙(바뀌면 userCred·세션·증명 캐시 폐기).
- **트랜잭션**: 세션 선택 → (`Selective disclosure proof` 버튼이면 AttrGate 대상·조건 자동) → 공개 조건 정규화(`normalizeDisclosure`·`normalizeSet`, 불만족 조건 제외) → 동기화(§4.3) → π_RP(워커, 캐시 조건 같으면 재사용) → `statementDigestFields`·`signPayload`(세션 개인키) → `execute` 호출 데이터 → `POST {RP}/api/mode3/relay`(§5.1) → txHash → RPC 로 영수증 → `parseExecuteReceipt` → `txs` 기록.
- **세션 폐기·자기 폐기·슬롯 요청**: 에이전트와 같은 메시지·서명(`signRevokeSession`·`signSlotRequest`), IdP 직접 호출.
- **시연 스위치**: `issue`·`prove`·`fake_proof`·`fake_sig` 는 페이지 내부 상태(`demo`)로 같은 의미.

### 4.2 RP 와의 팝업 프로토콜 (`?authorize=1`)
RP 가 `window.open('{user}/?authorize=1')` 로 팝업을 열고, 팝업이 `mode3-authorize-ready` 를 보내면 RP 가 요청을 보낸다. 요청 `type` 을 넓힌다(응답은 `…-result`, `r_s` 로 짝을 맞춘다, 대상 오리진은 양쪽 모두 고정):

| type | 요청 본문(기존 `/wallet/*` 본문과 같음) | 팝업 화면 | 응답 |
|---|---|---|---|
| `mode3-config` | — | 없음(즉시) | `{ secrets:'web', registered, uid?, rpCount }` (RP 의 `/wallet/config`+health 대체) |
| `mode3-precheck` | `{ arid, origin, cert_s, pk_trace, r_s, factoryAddress, attrGateAddress }` | 없음 | `{ ok } | { reason }` |
| `mode3-authorize` | 로그인 본문(기존) | 동의 화면(RP 이름·오리진·allowAgent) → 진행 | `{ ok, proof, publicSignals, sig, r_s, issued, timings, … }` |
| `mode3-revalidate` | `{ r_s, origin, skipSync? }` | 캐시 히트면 없음, 재증명이면 진행 화면 | 기존 `/wallet/revalidate` 응답 |
| `mode3-request` | `{ r_s, origin, body }` | 동의 화면("이 요청에 세션키로 서명") | `{ ok, sig }` |

RP 페이지는 web 모드에서 위 다섯 메시지만 쓴다(`walletMode === 'web'` 분기; file/snap 모드 코드는 그대로 남긴다). 팝업은 `verifiedOrigin = event.origin` 을 요청의 `origin` 과 대조하고(지금 규칙), 세션의 `origin` 과 다른 RP 가 `revalidate`·`request` 를 보내면 `bad_rp_cert` 로 거절한다.

### 4.3 체인 동기화
브라우저 ethers `JsonRpcProvider('http://127.0.0.1:8545')` 로 `Mode3Mirror`/`Mode3Log` 이벤트를 읽어 `syncRevocationTree`·`syncRegistryTree`(공유 코드)를 돌린다. 체크포인트는 `rcl` 에 둔다. hardhat 은 CORS `*` 를 허용하므로 추가 설정이 없다. RP 의 `MODE3_MAX_ROOT_AGE` 규칙(stale root → `registry_unpublished`·`root_too_old`)은 그대로다.

## 5. 서버 변경

### 5.1 RP 릴레이 `POST /api/mode3/relay`
사용자 페이지(오리진 :5100)가 RP 오리진으로 부르므로 이 라우트(와 `GET /api/mode3/relay/:txHash`)에 **사용자 오리진 CORS** 를 허용한다(`WALLET_ORIGIN`, 지금 health 가 쓰는 `originList` 와 같은 방식). 본문 `{ to, data, value? }` (`value` 는 0 고정, 받으면 400). 검사 순서: (1) RP 활성(`verifier`), (2) `to` 가 **이 RP 팩토리의 계정**(`factory.isWallet(to)` 또는 `computeAddress(PPID)` 대조 — 로그인 기록의 PPID 중 하나), (3) `data` 의 셀렉터가 `Mode3Wallet.execute`, (4) `decodeExecuteCalldata` 가 성공하고 `pub` 길이 33·`pub[1] === arid`, (5) `estimateGas` ≤ `MODE3_RELAY_GAS_CAP`(기본 1,200,000), (6) 속도 제한(계정당 분당 `MODE3_RELAY_RATE`, 기본 10). 통과하면 릴레이어 서명 계정으로 전송하고 `{ txHash }` 를 돌려준다. 실패는 `{ reason }`: `relay_inactive`(503)·`relay_bad_target`·`relay_bad_calldata`(400)·`relay_gas`(400, estimateGas revert 사유 포함)·`relay_rate_limited`(429). `GET /api/mode3/relay/:txHash` 는 영수증 유무만 돌려준다(페이지는 RPC 로도 볼 수 있다). 릴레이어는 **서명만** 하므로 사용자 비밀을 보지 않는다. 검열 가능성은 §9.

### 5.2 RP 페이지(`mode3/rp.html`)
`walletMode` 판정: 팝업 `mode3-config` 응답의 `secrets`(`web`)로. web 모드에서 `/wallet/*` fetch 금지, 재검증·요청은 팝업. 그 밖(로그인 창·zkONE/zkTWO·승인 개봉)은 그대로.

### 5.3 IdP CORS
`cia.js` 에 사용자 오리진(`MODE3_WALLET_AGENT_ORIGIN`, 기본 `http://127.0.0.1:5100`) 을 `/cia/register`·`/cia/issue`·`/cia/slot`·`/cia/revoke`(scope=session, 사용자 서명)·`/cia/attr_schema`·`/cia/public_keys`·`/cia/self_revoke`(있으면)에 허용한다(`Access-Control-Allow-Origin` 고정값, preflight 응답). 관리자 라우트는 허용하지 않는다.

### 5.4 Node 에이전트
변경 없음(D4). 단 정적 서버와 포트가 같으므로 둘을 동시에 띄우지 않는다(런북).

## 6. 공유 라이브러리의 브라우저화

| 파일 | Node 전용 | 조치 |
|---|---|---|
| `lib/mode3_credential.js` | `randomBytes` | `lib/browser/random.js`(`crypto.getRandomValues`)로 교체 — esbuild `alias`(`node:crypto` → shim). 서버 코드는 그대로 Node 모듈을 쓴다. |
| `lib/mode3_wallet.js` | `path`·`fileURLToPath`·`randomBytes`, `WASM_PATH`·`ZKEY_PATH`·`VKEY_PATH` | 경로 상수는 호출자가 넘기는 `assets` 객체(`{ wasm, zkey, vkey }` = URL 또는 ArrayBuffer)로 바꾸는 **선택적 인자**를 추가(기본값은 지금 경로 — Node 호환 유지). `buildCredentialProof`·`proveIdp` 가 `snarkjs.groth16.fullProve(input, wasm, zkey)` 에 Uint8Array 를 넘긴다(snarkjs 는 경로·버퍼 둘 다 받는다). |
| `lib/mode3_idp_proof.js` | `fs`·`path` | 같은 방식(`assets` 인자, `loadIdpVkey(url|json)`). |
| `lib/mode3_onchain.js` | `fs`·`path`(ABI/참조 코드 읽기) | ABI 는 이미 상수. 참조 코드 대조(`verifyReferenceCode`)는 아티팩트 JSON 을 `/zk/artifacts/*.json` 으로 서빙하거나 **web 모드에서는 생략**(팩토리 코드 대조는 RP 의 책임으로 두고 한계에 적는다) — 생략을 택한다. |
| `lib/mode3_attr_schema.js` | `createHash`(문자열 속성 해시, 동기) | 브라우저에서는 SHA-256 을 동기로 계산할 WebCrypto 가 없다 → `encodeProfile` 을 **async 로 바꾸지 않고**, 문자열 해시 함수를 주입식(`setStringHasher(fn)`)으로 두어 브라우저 번들이 작은 순수 JS SHA-256(의존성 없이 `lib/browser/sha256.js` 직접 구현, 테스트 벡터 포함)을 꽂는다. |
| `lib/mode3_log.js`·`mode3_revocation.js`·`mode3_registry.js`·`mode3_set_tree.js` | 없음(2026-10-15 grep 확인) | 그대로. |
| `lib/mode3_rp_cert.js`·`mode3_trace.js`·`mode3_rcl_sync.js`·`mode3_state.js`·`transition_proof.js` | `node:crypto`(randomBytes·createHash)·`fs` 중 일부(2026-10-15 grep) | 사용자 페이지가 쓰는 함수만 가려 같은 shim(`random.js`·`sha256.js`)으로 해결; `mode3_state.js`·`transition_proof.js` 는 사용자 페이지가 쓰지 않으면 번들에서 제외. 계획 단계에서 함수별로 확인한다. |

빌드: `scripts/build_user_app.sh` → `npx esbuild mode3/user/user.js --bundle --format=esm --platform=browser --alias:node:crypto=./lib/browser/node_crypto.js --outfile=mode3/user/dist/user.js` + `worker.js` 동일. `circomlibjs`·`snarkjs`·`ethers` 는 번들에 포함(오프라인 데모). COOP/COEP 아래에서 snarkjs 의 워커 스레드가 `SharedArrayBuffer` 를 쓴다.

증명 워커: 메시지 `{ kind:'pi_idp'|'pi_cred', input, assets }` → `{ proof, publicSignals, ms }`. zkey 는 첫 요청 때 `/zk/pi_cred_final.zkey` 를 `fetch` 해 Cache API(`mode3-zk-v1`)에 두고 진행률을 페이지에 보낸다(`{ kind:'progress', loaded, total }`). vkey 로 자기 증명을 한 번 검증해 산출물 짝을 확인한다(에이전트의 artifacts 검사 대체).

## 7. 화면

`mode3/user/index.html` 은 지금 `mode3/wallet.html` 의 카드 구성을 유지한다(사용자 속성 등록·로그인 세션·트랜잭션 보내기·시연·전문가 보기). 달라지는 것: (1) 상단 "잠금 해제/잠그기" 와 비밀번호 창, (2) "MetaMask · Snap" 카드 대신 "보관 상태"(IndexedDB, 마지막 잠금 해제 시각, "모두 지우기"), (3) 첫 사용 때 zkey 다운로드 진행률, (4) 팝업 모드(`?authorize=1`)의 동의 화면이 Snap 동의 창을 대신한다(RP 이름·오리진·요청 종류·allowAgent). 문구는 `strings.js` 에 `user_*` 키로 추가하고 `data-page="wallet"` 을 유지해 체험 모드 단계·안내 바를 그대로 쓴다.

## 8. 오류·사유

기존 사유 체계를 그대로 쓰고 다음을 더한다: `locked`(비밀번호 미해제 — 창을 띄우고 재시도), `bad_password`, `zk_assets_unavailable`(다운로드·검증 실패; 진행률·재시도), `relay_*`(§5.1), `chain_unavailable`(RPC 불가), `storage_unavailable`(IndexedDB 불가 — 사생활 보호 모드 등). `strings.js` `reasons` 에 ko/en 과 `where`(`wallet`·`rp`)를 넣는다.

## 9. 보안·프라이버시 메모

- 비밀의 격리 수준이 Snap(확장 프로그램 샌드박스·사용마다 동의)에서 **페이지 자체**(IndexedDB, 같은 오리진 스크립트가 읽을 수 있음)로 내려간다. XSS 한 건이면 비밀이 새고, 사이트 데이터 삭제로 사라진다. 비밀번호 기반 암호화는 저장 중(at rest) 보호만 준다. 데모 한계로 명시.
- 릴레이: RP 가 트랜잭션을 거부·지연할 수 있다(검열). 사용자 비밀·π 의 내용은 지금도 RP 가 보던 것 이상을 보지 않는다(π_RP 와 공개 입력은 로그인에서 이미 받는다). EOA 가 드러나는 스냅 모드의 한계는 없어진다.
- V11 의 알려진 노출(auid_s·arid_s 가 calldata 에 올라감)은 그대로다 — 별도 결정.
- 팝업 오리진 검사·CORS 고정 오리진·`value=0` 강제로 RP 가 사용자 자금을 쓸 길은 없다(계정에 잔고가 있어도 `execute` 의 value 는 사용자가 서명한 statement 안에 있다).

## 10. 런북·운영

- `npm run user:build`(esbuild) → `node mode3_user_static.js`(:5100). file/snap 모드 에이전트와 포트가 같으니 둘 중 하나만.
- RP 는 `MODE3_RELAY_GAS_CAP`·`MODE3_RELAY_RATE` 선택 env. IdP 는 변경 env 없음.
- 다른 기계: `build/mode3` 묶음(이미 pi_idp 포함)만 있으면 됨. 브라우저는 Chrome/Edge/Firefox 최신(SharedArrayBuffer 는 COOP/COEP 아래에서만).
- 재시연 세트에 "브라우저 사이트 데이터(127.0.0.1:5100) 삭제 또는 페이지의 '모두 지우기'" 를 추가한다(Snap 초기화에 해당).

## 11. 테스트

- `tests/test_mode3_user_web.mjs`(browser 그룹, Chrome 필요): 정적 서버 + 격리 IdP/RP(기존 헬퍼)에서 등록 → 로그인(팝업) → 재검증 → 세션 요청 → 평범한 트랜잭션(릴레이) → Selective disclosure proof → 세션 폐기 → 잠금/해제 → 가짜 증명·서명 거절. 격리 스택 헬퍼에 `userMode:'web'` 옵션(정적 서버 기동).
- `tests/test_mode3_rp_relay.mjs`(chain): 릴레이 검사 6단계 각각의 음성(비활성·다른 팩토리 계정·셀렉터·pub[1]·가스 상한·속도 제한)과 양성.
- `tests/test_cia_cors.mjs`(chain, 가벼움): 허용 라우트의 preflight·헤더, 관리자 라우트는 불허.
- `lib/browser/sha256.js` 단위 테스트(테스트 벡터)와 `encodeProfile` 의 주입 해시가 Node 결과와 같음을 확인하는 단위 테스트(unit 그룹).
- 기존 그룹 전부 통과 유지(에이전트 불변).

## 12. 범위 밖·후속

Snap 모드·Node 에이전트 변경, 패스키(WebAuthn), npm Snap 게시, 독립 릴레이어, 모바일 브라우저 최적화, V11 노출(auid_s) 설계 변경.
