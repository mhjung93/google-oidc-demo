# Mode 3 OIDC 래퍼 — Snap 모드(분리 VM 데모) 지원 설계

- 작성: 2026-10-26
- 선행 스펙: `2026-10-16-mode3-oidc-wrapper-design.md`(래퍼 본체, §8 에서 Snap·에이전트 모드를 비범위로 남김)
- 범위: `MODE3_WALLET_SECRETS=snap` 지갑(에이전트 :5100 + MetaMask Snap)에서 Google 계정 **등록 → RP 로그인(발급) → 자기 폐기**가 동작하게 한다. 분리 VM 데모(`scripts/demo_split_start.sh`, `WALLET_MODE=snap`)가 대상이다.

## 1. 배경과 제약

- 래퍼는 지금 web 사용자 페이지(브라우저 전용)와 IdP `/account` 에만 있다. 분리 데모의 IdP 는 사설 IP(`192.168.226.10:4100`)에 있어 Google GSI 가 뜨지 않는다 — GSI 는 등록된 JavaScript 오리진에서만 동작하고, 이 데모에서 쓸 수 있는 것은 `http://localhost:5100`(지갑 페이지·팝업)뿐이다(`Mode3Gsi.originOk()`).
- IdP 의 검증 로직(`/cia/register`·`/cia/issue`·`/cia/account/self_revoke` 의 `id_token` 경로, nonce 3종)은 이미 있다. 이 작업은 **지갑 쪽이 토큰을 받아 오는 경로**를 만드는 것이다.
- 사용자 결정(2026-10-25 브레인스토밍):
  - D1. 등록 토큰의 nonce 는 지금처럼 `reg:H(pk_u)` 에 묶는다 → Snap 이 uid 를 알기 **전에** 비밀을 만들어야 하므로 Snap 을 고친다(번들 재빌드·MetaMask 재설치).
  - D2. 등록 진입점은 IdP `/user` 페이지 버튼 → 지갑 팝업. Google 로그인은 팝업(localhost:5100) 안에서 한다.
  - D3. 클라이언트 ID 는 Mode 1 공유 `GOOGLE_CLIENT_ID`. 분리 스크립트가 `.env` 에서 출력 없이 읽어 IdP VM 에 `MODE3_OIDC_CLIENT_ID` 로 넘긴다. 공유 ID 위험은 선행 스펙 §5 그대로다(IdP 가 기동 때 경고).

## 2. 흐름

### 2.1 등록

1. `/user`(IdP) — `public_keys.oidc.enabled` 일 때만 "Google 로 등록" 버튼이 보인다. IdP 로그인·`register_code` 가 필요 없다. 누르면 `${walletOrigin}/?authorize=1` 팝업을 열고, `mode3-authorize-ready` 를 받으면 `{ type:'mode3-register', provider:'google', ciaUrl }` 를 보낸다(uid·code 없음). 결과는 기존 데모 등록처럼 `mode3-register-result` 로 받는다.
2. 팝업 `handleRegisterMessage` 의 Google 분기:
   1. 오리진 검사(`cfg.ciaUrl`) → MetaMask 연결 → `/wallet/status` 이미 등록 검사(기존과 같다).
   2. **Snap `prepareRegister`** — 확인 창("Google 계정 등록: 등록 비밀을 만들어 이 Snap 에 보관합니다")을 띄우고, 승인하면 `s_u·sk_u` 를 만들어 **uid 없는 보류 등록**으로 저장한 뒤 `{ s_u, sk_u }` 를 돌려준다. 거절이면 `{ denied:true }`.
   3. 에이전트 `POST /wallet/oidc/nonce { purpose:'register', sk_u }` → `{ nonce: regNonce(pk_u) }`(pk_u 는 sk_u 로 계산, 저장하지 않는다).
   4. 팝업이 `Mode3Gsi.render({ clientId: cfg.oidc.clientId, nonce, onToken })` 로 Google 버튼을 그린다(사용자 클릭 필요 — GSI 정책).
   5. 토큰 → 에이전트 `POST /wallet/register { id_token, s_u, sk_u, profile? }`. 에이전트는 토큰 페이로드의 `sub` 를 **서명 검증 없이** 읽어 `uid = uidOf(oidc.provider, sub)` 를 계산하고(검증은 IdP 몫 — 틀린 토큰이면 IdP 가 401), auid·pk_u·sig_reg 를 만들어 `/cia/register { id_token, auid, pk_u, sig_reg }` 로 보낸다. IdP 응답의 `uid` 가 자기가 계산한 값과 다르면 502 `uid_mismatch`. 성공하면 등록에 `provider` 를 함께 저장한다.
   6. Snap `storeRegistration { attrs, slot, auid, uid, provider }` — 보류 등록에 uid 를 채운다. 응답을 `mode3-register-result` 로 돌려준다.
3. 실패 처리: 5 에서 실패하면 Snap 에는 보류 등록이 남는다. 다시 시도하면 `prepareRegister` 가 **같은 보류 비밀을 다시 돌려준다**(확인 창은 다시 띄운다) — 같은 pk_u 이므로 nonce 도 같다. Snap 은 그대로 두고 에이전트·IdP 만 다시 시도하면 된다. 버리려면 `reset`.

### 2.2 RP 로그인(발급)

- `runAuthorize()` 는 Snap `consentLogin` 까지 지금과 같다. 그다음 `/wallet/status` 의 `provider` 가 `demo` 가 아니면 IdP 인증 창(`/login`) 대신 다음을 한다:
  1. 에이전트 `POST /wallet/oidc/nonce { purpose:'issue', arid, r_rp }` → `issueNonce(registration.pk_u, aridSOf({ arid, r_rp }))`.
  2. 팝업에 Google 버튼 → 토큰.
  3. `/wallet/login { …, id_token }`. 에이전트 `issueSession` 이 `auth_code` 와 같은 방식으로 `req.body.id_token` 을 싣는다(재시도 경로도 같은 토큰을 그대로 싣는다 — 같은 arid_s 다).
- `provider` 가 `demo` 면 지금처럼 IdP 인증 창(`ISSUE_AUTH=code`). RP·IdP 변경 없음.

### 2.3 자기 폐기

- 지갑 페이지 `#selfRevokeBtn`: `provider` 가 `demo` 면 지금처럼 Snap `selfRevoke`(비밀번호 프롬프트) → `/wallet/self_revoke { uid, pwd }`.
- Google 계정이면 확인(confirm) 뒤 에이전트 `POST /wallet/oidc/nonce { purpose:'revoke' }` → `newRevokeNonce()` → Google 버튼 → `/wallet/self_revoke { id_token }`. 에이전트는 토큰의 `sub` 로 계산한 uid 가 자기 등록 uid 와 같을 때만 `/cia/account/self_revoke { id_token }` 로 중계한다(다르면 403 `uid_mismatch` — 기존 "이 지갑이 든 계정만 중계" 규칙과 같다).

## 3. 바뀌는 곳

| 구성요소 | 변경 |
|---|---|
| `snap-mode3/src/index.js` | `prepareRegister` 추가(확인 창, uid 없는 보류 등록, 보류가 있으면 같은 비밀 반환, 완성 등록이 있으면 `already_registered`). `storeRegistration` 이 `uid`·`provider` 를 받는다 — 보류 등록에는 uid 를 채우고, uid 가 이미 있으면 같은 값일 때만 받는다(다르면 `uid_mismatch`). `getPublicInfo` 의 `registered` 는 uid 가 있을 때만 true, `pending`·`provider` 추가. `register`·`reset` 은 그대로(reset 이 보류도 지운다 — 상태 전체 삭제). |
| `tests/helpers/snap_sim.mjs` | 위 RPC 를 같은 입출력으로(파일 머리 규칙: index.js 와 입출력 동일). |
| `mode3_wallet_agent.js` | `POST /wallet/oidc/nonce`(register·issue·revoke, 비밀 저장 안 함, CORS 없음 — 지갑 페이지 같은 오리진 전용). `/wallet/register` 의 `id_token` 경로(uid 를 토큰에서 계산, `id_token` 과 `uid/pwd/code` 를 함께 주면 400). 등록에 `provider` 저장(데모 등록은 `'demo'`), `/wallet/status` 에 `provider`. `/wallet/login` 이 `id_token` 을 받아 `issueSession` 에 넘김. `/wallet/self_revoke` 의 `id_token` 경로. `/wallet/config` 에 `oidc`(IdP `/cia/public_keys` 의 `oidc` 를 그대로 — 기동 뒤 첫 요청에서 읽고 캐시). |
| `mode3/wallet.html` | 등록 메시지의 Google 분기, `runAuthorize` 의 Google 단계, 자기 폐기 Google 분기. GSI 버튼을 그릴 자리(팝업·지갑 페이지 공용 1곳). `/common/gsi.js` 를 불러 쓴다(에이전트가 `/common` 을 이미 서빙한다 — 정적 경로 변경 없음). |
| `mode3/cia_user.html` | "Google 로 등록" 버튼(위 §2.1-1). 지갑 오리진은 기존 상태 패널이 health 에서 얻는 `walletOrigin` 을 쓴다(없으면 버튼 비활성). 기존 데모 등록 버튼은 그대로. |
| `scripts/demo_split_start.sh` | IdP role.env 에 `MODE3_OIDC_CLIENT_ID` 를 쓴다. 값은 환경변수 `MODE3_OIDC_CLIENT_ID` 가 있으면 그것, 없으면 `.env` 의 `GOOGLE_CLIENT_ID` 줄을 출력 없이 추출. `OIDC=0` 이면 쓰지 않는다(래퍼 꺼짐). 값은 어디에도 echo 하지 않는다(진행 줄은 "OIDC: on/off" 만). |
| `docs/MODE3_DEMO.md` | 분리 데모 런북에 Google 절: Google 콘솔의 승인된 JavaScript 오리진에 `http://localhost:5100` 이 있어야 함, Snap 재빌드·MetaMask 재설치, 수동 체크리스트. |
| IdP(`cia.js`) | 변경 없음. |

## 4. 오류

- 토큰이 틀리거나 만료됨 → IdP 401 `oidc_invalid` 를 에이전트가 그대로 넘기고 팝업에 표시한다. 다시 Google 버튼을 누르면 된다.
- nonce 불일치 → IdP 400 `oidc_nonce_mismatch`. 정상 흐름에서는 나지 않는다(나면 버그 — 그대로 표시).
- IdP 래퍼 꺼짐 → `/wallet/config.oidc.enabled=false` 이므로 버튼이 안 보인다. 그래도 들어오면 IdP 503 `oidc_disabled`.
- GSI 로드 실패·오리진 불가(`originOk()` false) → 팝업에 "Google 로그인은 http://localhost:5100 에서만 됩니다" 를 띄우고 그 흐름을 끝낸다.
- Google 계정인데 발급 요청에 토큰이 없음 → IdP 401 `oidc_required`(옛 페이지·직접 호출). 그대로 표시.
- 자기 폐기 토큰의 계정이 이 지갑과 다름 → 에이전트 403 `uid_mismatch`.

## 5. 보안 메모

- 에이전트는 토큰 서명을 검증하지 않는다 — uid 를 미리 계산하는 데만 쓰고 판정은 IdP 가 한다. 위조 토큰으로 얻는 것은 IdP 의 401 뿐이다.
- `/wallet/oidc/nonce` 는 비밀을 내지 않는다(nonce 는 pk_u·arid_s 의 해시). register 용 호출은 sk_u 를 받지만 pk_u 계산에만 쓰고 저장·로그하지 않는다 — 같은 페이지가 바로 다음에 `/wallet/register` 로 같은 sk_u 를 보내므로 노출면이 늘지 않는다.
- id_token 은 에이전트 로그·상태 파일에 남기지 않는다(`auth_code` 와 같은 규칙).
- 공유 클라이언트 ID 위험은 선행 스펙 §5 와 같고 이 작업이 바꾸지 않는다.

## 6. 테스트

- `snap` 그룹: `prepareRegister`(승인·거절·보류 재반환·완성 등록이면 already_registered), `storeRegistration` 의 uid 채움·불일치 거절, `getPublicInfo` 의 registered/pending, reset 이 보류를 지움.
- `chain` 그룹(에이전트 snap 모드, `startIsolatedCia({ oidc: true })` + `oidc_issuer_stub`): Google 등록 → 발급(id_token) → 자기 폐기(id_token) → 다음 발급 거절. 그리고 `/wallet/oidc/nonce` 세 목적의 값이 `lib/mode3_oidc_nonce.js` 와 같음, 토큰 없는 발급의 `oidc_required` 전달, 다른 계정 토큰의 자기 폐기 403.
- `browser` 그룹 1건: `accounts.google.com/gsi/client` 를 Playwright route 로 스텁(`google.accounts.id.initialize/renderButton` 이 버튼 클릭 때 스텁 발급자가 그 nonce 로 서명한 토큰을 callback 에 넘김)으로 바꿔 `/user` → 팝업 → Google 등록 → RP 로그인까지.
- 실제 Google 은 런북 수동 체크리스트로 1회 확인한다(자동 테스트 아님).
- 새 테스트는 `scripts/run_tests.sh` 의 해당 그룹에 넣는다.

## 7. 비범위

- 래퍼 계정의 복구(복구 코드 설계 2026-10-21 과의 결합).
- 분리 구성에서 IdP `/account` 페이지의 Google 자기 폐기(IdP 가 사설 IP 라 GSI 불가 — 지갑 페이지 경로로 대신한다).
- 공유 클라이언트 ID 위험의 근본 해결(전용 클라이언트 ID 발급).
- file 모드 지갑의 래퍼 지원(이번 대상은 Snap 모드).
