# Mode 3 — 사용자 속성 커밋먼트를 zkID ID 토큰 `name` 으로 RP 에 전달 설계

- 작성: 2026-11-06, **개정: 2026-11-09**(사용자 결정 반영 — 커밋먼트에 RP 값 없음·계산은 독립 정적 페이지·IdP 최소 관여·Phase 1 구현).
- 선행 스펙: `2026-10-12-mode3-v11-figure-protocol-design.md`(V11 — D15 "속성은 사용자가 넣고 IdP 는 모른다"), `2026-10-16-mode3-oidc-wrapper-design.md`·`2026-10-26-mode3-snap-oidc-wrapper-design.md`(OIDC 래퍼 — Google 경로), 속성 매핑 스펙 2(`lib/mode3_attr_schema.js`).
- 범위: 사용자가 **지갑·IdP·RP 어디와도 통신하지 않는 독립 정적 페이지**(속성 도구)에서 속성 커밋먼트 `C_attr` 를 만들고, 그 값을 **zkID 프로필의 `name` 칸**에 직접 붙여 넣는다. zkID(IdP, `cia.js`)는 세션 발급 때 **OIDC 모양의 ID 토큰**(`sub=auid_s`, `aud=arid_s`, `name=C_attr`)을 함께 내고, 지갑은 열어 보지 않고 RP 에 전달하며, RP 는 토큰을 검증해 `name` 을 계정(PPID)에 고정한다. 2단계에서 같은 도구 페이지가 그 커밋먼트를 여는 속성 증명(`pi_attr`)을 만들어 RP 에 팝업으로 넘긴다.
- 비범위: Google(외부 OIDC) 경로(§9), IdP 가 값을 검증·보증하는 속성(KYC 류) — D15 는 그대로다. 발급 때 지갑 키를 IdP 가 모르게 묶는 nonce 설계, 등록부·폐기 게시·RP 인증서·개봉을 IdP 밖으로 빼는 분리(ZDS)는 후속(§11).

## 0. 한 줄 요약

사용자가 독립 페이지에서 만든 속성 커밋먼트를 zkID 프로필 `name` 에 붙여 넣으면, zkID 는 그 뜻을 모른 채 **표준 OIDC 프로필 클레임(`name`)에 실은 ID 토큰**으로 서명해 지갑에 주고, 지갑은 RP 로그인 때 토큰을 함께 내며 RP 는 `name` 을 계정에 고정한다 — "IdP 는 사용자 속성 커밋먼트를 저장하는 것 말고는 zk-Delegation 에 관여하지 않는다"(래퍼 역할).

## 1. 사용자 결정

| # | 결정 | 날짜 | 비고 |
|---|---|---|---|
| D1 | 커밋먼트는 **OIDC 프로필 클레임 중 안 쓰는 칸**에 넣는다. 칸은 **`name`**. | 11-06 | `email`·`birthdate` 처럼 형식이 고정된 칸은 제외. `name` 은 자유 문자열이고 `profile` scope 로 늘 실린다. |
| D2 | **`profile` scope 는 무조건 포함**한다. | 11-06 | zkID 토큰에는 `name` 을 늘 싣는다(프로필이 있을 때). RP 가 scope 를 고르지 않는다. |
| D3 | 이 기능은 **zkID 가입 때가 아니라 RP 에 등록(첫 로그인)할 때** 쓰인다. | 11-06 | RP 가 토큰에서 커밋먼트를 받아 계정에 묶는다. |
| D4 | 토큰은 **zkID 가 발급하고 지갑이 RP 에 전달**한다(1안). "그게 래퍼 역할이니까." | 11-06 | RP 는 IdP 와 직접 통신하지 않는다(RP-hiding 유지). JWKS·discovery 만 서버 간 읽는다. |
| D5 | **IdP 는 사용자 속성 커밋먼트를 저장하는 것 말고는 zk-Delegation 에 관여하지 않는다.** 등록 당시 IdP 는 지갑을 모른다. 위임 인증(delegated authentication)은 지금처럼 진행한다. 폐기 게시도 (일단) IdP 가 하지 않는 것으로 둔다. | 11-09 | 이번 Phase 1 은 커밋먼트 경로만 바꾼다. 등록·게시의 분리는 §11 후속. |
| D6 | 커밋먼트 등록은 **MetaMask·Snap 과 완전히 별개** 흐름이다 — 지갑에서 자동 전송하지 않는다. | 11-09 | "커밋먼트를 지갑에서 자동 전송하면 결국 지갑이 필요하다." |
| D7 | **커밋먼트에는 RP 관련 값이 전혀 없다**(arid 등 제외). | 11-09 | 11-06 초안의 `arid` 포함을 뒤집었다. 사용자가 어느 서비스에 내든 같은 값. |
| D8 | 계산은 **IdP 페이지가 아니라 별도 프로그램(독립 정적 페이지)** 에서 한다 — IdP 페이지에서 salt(blind)를 다루면 프라이버시 문제. 사용자가 결과를 IdP 에 **붙여 넣는다**. | 11-09 | 도구는 서버와 통신하지 않는다. |
| D9 | 도구 페이지는 Snap 과 잇지 않고 **독립 정적 페이지가 모든 것(계산·비밀 보관·뒤의 속성 증명)을 수행**한다. | 11-09 | |
| D10 | 서빙은 **`localhost:5100`(지갑 에이전트 오리진)에 다 몬다** — `/attr.html`. | 11-09 | 같은 오리진에 두는 것은 주소 하나로 데모를 돌리기 위해서다. 에이전트 API 는 부르지 않는다. |
| D11 | 증명(2단계)은 **팝업/postMessage** 로 RP 에 넘긴다. | 11-09 | 사용자가 복사-붙여넣기 하지 않게. |
| D12 | **"일단 그 상태로 데모 한 번"** — Phase 1 을 지금 구현한다. | 11-09 | |
| D13 | **zkID 페이지에 지갑 등록이 없어야 한다** — 등록 과정에는 지갑 연결이 아예 없고, 지갑(MetaMask)은 위임 인증(RP "zkID 로 로그인") 때 처음 붙는다. 미등록 지갑의 첫 로그인이 곧 등록이다(인증 창 등록 모드 → 등록 코드 → `/cia/register` → 함께 받은 발급 코드로 발급). | 11-09 | `/user` 의 "커밋먼트 등록" 카드 제거. IdP 가 `pk_u`·`auid` 를 저장하는 프로토콜은 유지(§11). |

## 2. 배경과 제약(현재 코드)

- 속성(D15): 지갑(Snap)에만 있다. `C_u = uid·G + s_u·G + Σ attrs[k]·G_k + blind_u·H`, IdP 는 `Cf_u = H(C_u)` 만 받고 등록부 리프 `Poseidon(auid, Cf_u)` 에 넣는다. 스키마 `zkd-attrs v1`: 슬롯 0 `birthYear`, 1 `country`, 2 `extra1`(string), 3 `extra2`(string), 4·5 unused. 이 `C_u` 는 그대로다 — `C_attr` 는 **별개의 두 번째 커밋먼트**다.
- 발급(`POST /cia/issue`, V11): 응답의 자격증명은 `Sign_EdDSA(Poseidon(D, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent))`. RP 는 IdP 로부터 아무것도 직접 받지 않는다(RP-hiding — IdP 는 `arid` 를 모르고 세션 가명 `auid_s = H(auid, arid, r_rp)`, `arid_s = H(arid, r_rp)` 만 본다).
- RP 로그인: 지갑 팝업이 `(proof, publicSignals[34], sig)` 를 `mode3-login-result` 로 RP 페이지에 넘기고, RP 페이지가 `POST /api/mode3/login { proof, publicSignals, sig, r_s, require }`. 공개 입력에 `AUID_S`(30)·`ARID_S`(31)가 있다.
- 의존성: `jose@^5`(이미 있음), `esbuild`(web 모드 번들에 이미 씀), `circomlibjs`. 새 의존성 없음. `jose@5` 는 ES256K 를 지원하지 않으므로 이더리움 키로 서명하지 않고 P-256 키를 새로 둔다.
- 제약: 회로(`pi_cred`·`pi_idp`)와 온체인 검증기(`pub` 34칸)는 바꾸지 않는다(2단계에서 소형 회로를 **추가**할 뿐).

## 3. 사용자 속성 커밋먼트 `C_attr`

- 정의: **`C_attr = Poseidon(T_ATTRC, attrs[0], …, attrs[5], blind)`**(BN254 스칼라, 10진 문자열로 운반). `lib/mode3_attr_commit.js` `attrCommit({ attrs, blind })`.
  - 입력은 스키마 인코딩된 속성 6칸 전부(`encodeProfile`) — 지갑의 `C_u` 와 같은 인코딩이라 2단계 증명이 "같은 속성" 임을 보일 여지를 남긴다. **RP 값은 없다**(D7).
  - `blind`: 도구 페이지가 만들 때마다 새로 뽑는 31바이트 난수. 속성을 바꾸거나 다시 만들면 새 blind → 옛 커밋먼트와 연결되지 않는다.
  - `T_ATTRC = 365084431357309388870211`(ASCII "MODE3ATTRC" 빅엔디언, 다른 도메인 상수와 같은 방식).
- **IdP 는 `C_attr` 를 검증하지 않고 뜻도 모른다** — 사용자가 `name` 칸에 적은 문자열을 서명해 주는 표준 IdP 와 같다. 커밋먼트가 실제 속성을 여는지는 **RP 앞에서 도구 페이지가 만드는 증명**(§7 2단계)이 보인다.
- 비연결성 메모(D7 의 대가): `C_attr` 는 RP 마다 같으므로 **두 RP 가 `name` 을 맞대면 같은 사용자임을 알 수 있다**(PPID 는 RP 마다 다르지만 커밋먼트는 같다). 사용자 결정으로 수용한다 — 필요하면 RP 마다 도구에서 새로 만들어(새 blind) 각 RP 에 다른 값을 넣으면 된다(도구는 하나만 보관하므로 백업으로 돌려 쓴다). §11.

## 4. 속성 도구 페이지(`mode3/attr.html`, 2026-11-09)

- 지갑 에이전트가 `GET /attr.html` 로 서빙하는 **독립 정적 페이지**. 번들 `mode3/attr/dist/attr.js`(`npm run attr:build` → esbuild IIFE `window.Mode3Attr`, `lib/browser/` shim 으로 `node:` 모듈 대체 — `build_user_app.mjs` 와 같은 방식, 출력은 `.gitignore`).
- 하는 일: 속성 입력(스키마 폼: 출생연도·국가·예비 1·2) → `encodeProfile(…, { allowEmptyRequired: false })` → 새 `blind` → `C_attr` → **localStorage `mode3_attr_tool_v1`** `{ version:1, schema:{id,version}, profile, attrs, blind, commit, createdAt }` → 커밋먼트 표시·복사. 백업 내려받기/불러오기(불러올 때 커밋먼트를 다시 계산해 맞춰 본다), 지우기(confirm).
- 하지 않는 일: 어떤 서버에도 요청하지 않는다(정적 자원 `/attr.html`·`/attr/dist/*`·`/common/*` 뿐 — 브라우저 테스트가 요청 목록으로 확인한다). MetaMask·Snap·에이전트 API 와 무관. 에이전트의 `isPublicGet` 에 `/attr.html`·`/attr/*` 를 추가했다(상태를 읽지 않는 공개 GET).
- 2단계(§7): 같은 저장값(`attrs`, `blind`)으로 `pi_attr` 증명을 만들어 RP 에 `?prove=1` 팝업 + postMessage 로 넘긴다(D11).

## 5. zkID — 프로필과 ID 토큰

### 5.1 프로필(`POST /cia/user/profile`, 사용자 세션)

- 본문 `{ name }` — 한 줄·256자 이하 문자열(제어 문자 거절 → 400 `bad_profile`), 앞뒤 공백 제거, 빈 값이면 지운다. `state.accounts[uid].profile = { name, updatedAt }`. `GET /cia/user/me` 에 `profile`.
- 지갑 등록 여부와 무관하게 로그인만 하면 된다(D6). `/user` 페이지의 "프로필" 카드 — 입력·저장·현재 값·"속성 도구 열기"(지갑 오리진 `/attr.html`) 링크.
- IdP 는 값을 해석하지 않는다. 관리자 화면에는 내지 않는다.

### 5.2 ID 토큰

- JWT `alg: ES256`, 헤더 `kid`. 서명 키는 `cia_keys.json` 의 **`idTokenJwk`**(P-256 개인 JWK, 첫 기동 때 `generateKeyPairSync` 로 생성, 기존 키 파일에 없으면 더한다 — EdDSA·ETH 키는 그대로라 재배포 연쇄 없음, 출력 금지).
- 발견 문서: `GET /.well-known/openid-configuration` → `{ issuer, jwks_uri, id_token_signing_alg_values_supported:['ES256'], subject_types_supported:['pairwise'], response_types_supported:['id_token'], claims_supported, scopes_supported:['openid','profile'] }`; `GET /.well-known/jwks.json` → 공개 JWK(`kid`·`use:'sig'`·`alg:'ES256'`, `d` 없음). 인증·CORS 없음.
- `issuer = CIA_PUBLIC_URL`(기본 `http://127.0.0.1:${CIA_PORT}`; 분리 데모 `demo_split_start.sh` 가 IdP role.env 에 `http://$IDP:$IDP_PORT` 를 넣는다).

| 클레임 | 값 | 비고 |
|---|---|---|
| `iss` | `CIA_PUBLIC_URL` | |
| `sub` | `auid_s`(10진) | 세션 가명 — RP 는 증명의 `auid_s` 와 같은지 본다. IdP 는 RP 를 모르므로 PPID 를 적을 수 없다. |
| `aud` | `arid_s`(10진) | 블라인딩된 RP 식별자 — RP 는 증명의 `arid_s` 와 같은지 본다. |
| `iat`·`exp` | 발급 시각, +10분 | 토큰은 그 로그인 1회용(`sub`·`aud` 결속). |
| **`name`** | 프로필의 `name`(= `C_attr`) | 프로필이 없으면 클레임 자체가 없다(토큰은 그래도 나온다). |

`nonce`·`preferred_username`·`updated_at`·`zkd_attr_schema`(11-06 초안)는 넣지 않았다 — 결속은 `sub`·`aud` 로 충분하고 나머지는 쓰는 곳이 없다(YAGNI).

- 발급 경로: `POST /cia/issue` 요청은 **바뀌지 않는다**(11-06 초안의 `attr_commit` 요청 필드는 없다 — D6·D8). 응답에 `id_token` 이 더해진다. 자격증명 메시지(`credMessageV11`)도 그대로.

## 6. 지갑·RP

- **에이전트**(`mode3_wallet_agent.js`): 세션 저장(`credential: r.body`)에 토큰이 함께 남고, `/wallet/login` 응답에 `id_token` 을 그대로 싣는다. 열어 보지 않는다. **지갑 페이지(`mode3/wallet.html`)·Snap 은 변경 없음** — 팝업은 이미 로그인 응답 전부(`toRp`)를 `mode3-login-result` 로 넘긴다.
- **RP 페이지**(`mode3/rp.html`): `POST /api/mode3/login { …, id_token }`. 세션 카드에 "속성 커밋먼트" 줄(앞 12자…뒤 6자, 툴팁 전체; 없으면 "없음"), localStorage 세션 복원에도 포함.
- **RP 서버**(`mode3_rp.js`):
  - 검증: `jose.jwtVerify(id_token, createRemoteJWKSet(CIA_URL + '/.well-known/jwks.json'), { issuer, audience: arid_s, algorithms:['ES256'] })` + `sub === auid_s`. `issuer` 는 `CIA_URL` 의 discovery 문서에서 읽어 캐시한다(실패는 캐시하지 않음). 어긋나면 `{ ok:false, reason:'bad_id_token' }` — 증명이 맞아도 로그인 실패. 토큰이 **없으면** 예전처럼 로그인한다(하위호환 — 옛 지갑·web 모드). 문자열이 아니거나 4KB 초과면 400 `malformed`.
  - 계정부(`mode3_rp_accounts.json`, 0600, env `MODE3_RP_ACCOUNTS_FILE`; `new_rp.sh` 는 `mode3_rp_<name>_accounts.json`): `byPPID[PPID] = { attrCommit, since, updatedAt, history[≤10] }`. 토큰의 `name` 이 커밋먼트 형식(`isAttrCommit` — 10진·필드 안)이면 처음엔 고정, 다르면 교체하며 `attrCommitChanged:true`(정책 env 는 두지 않았다 — 데모는 교체가 맞다). `name` 이 없거나 형식이 아니면 고정값을 건드리지 않는다.
  - 응답 `{ …, attrCommit, attrCommitChanged }`; `/api/mode3/sessions` 에 `attrCommit`.
  - 토큰은 저장하지 않는다(로그에도 안 남김).

## 7. 단계

### 1단계 — 도구·프로필·토큰·운반·RP 고정(회로 변경 없음) — **2026-11-09 구현**

§3·§4·§5·§6. 사용자가 "독립 도구에서 만든 커밋먼트가 zkID 를 불투명하게 거쳐 RP 계정에 묶이는 것"을 보일 수 있다. 커밋먼트가 실제 속성을 여는지는 아직 보이지 않는다.

### 2단계 — `pi_attr`: 사용자 속성 조건 증명(후속, 사용자 승인 뒤)

- 새 소형 회로 `circuits/pi_attr.circom`: 비공개 `attrs[6], blind`, 공개 `C_attr, disc_mask, disc_lo[6], disc_hi[6], set_sel, set_root`. 제약: `C_attr == Poseidon(T_ATTRC, attrs, blind)` + 선택 공개 범위/집합 술어(`pi_cred` ⑦ 과 같은 구조). Groth16, 오프체인 검증. 빌드는 별도 스크립트(`scripts/build_pi_attr.sh`) — 기존 zkey 를 건드리지 않는다.
- 도구 페이지: `attr.html?prove=1` 팝업 — RP 페이지가 `window.open` 으로 열고 postMessage 로 `{ require }` 를 보내면, 저장값으로 증명을 만들어 `{ proof, publicSignals }` 를 돌려준다(D11). 지갑 팝업 프로토콜(`mode3-login-result`)과 같은 모양.
- RP `POST /api/mode3/attr_proof { r_s, proof, publicSignals }`: 세션의 PPID 로 계정부의 `attrCommit` 을 찾아 공개 입력과 같은지, 술어가 정책을 만족하는지 본다 → 세션에 표시. 데모: zkTWO "속성 조건 확인" 카드.

## 8. 바뀐 곳(1단계, 실제)

| 구성요소 | 변경 |
|---|---|
| `lib/mode3_attr_commit.js`(신규) | `DOMAIN_MODE3_ATTRC`, `attrCommit`, `randomBlind`, `isAttrCommit`, `toField`. Node·브라우저 공용. |
| `mode3/attr.html`, `mode3/attr/attr_core.js`, `scripts/build_attr_tool.mjs`(신규), `package.json` `attr:build`, `.gitignore` `mode3/attr/dist/` | 속성 도구(§4). |
| `mode3_wallet_agent.js` | `/attr.html`·`/attr/*` 정적 서빙(공개 GET), `/wallet/login` 응답 `id_token`. |
| `cia.js` | `idTokenJwk`(P-256) 생성·보관, `/.well-known/*`, `CIA_PUBLIC_URL`, `POST /cia/user/profile`, `/cia/user/me.profile`, `/cia/issue` 응답 `id_token`. |
| `mode3/cia_user.html` | "프로필" 카드. |
| `mode3_rp.js` | `id_token` 검증(JWKS·discovery)·계정부·`attrCommit`/`attrCommitChanged`·세션 목록. |
| `mode3/rp.html` | 토큰 전달, 세션 카드 "속성 커밋먼트". |
| `mode3/common/strings.js` | `attr_*`·`idp_profile_*`·`rp_my_attr_commit` 문구, 사유 `bad_id_token`·`bad_profile`·`bad_backup`·`bundle_missing`. |
| 스크립트 | `demo_split_start.sh`: IdP role.env `CIA_PUBLIC_URL`. `new_rp.sh`: `MODE3_RP_ACCOUNTS_FILE`. |
| 문서 | `docs/MODE3_DEMO.md` "속성 커밋먼트(Phase 1)" 절·엔드포인트·테스트. |
| 테스트 | `tests/test_mode3_attr_commit.mjs`(unit), `tests/test_cia_accounts.mjs`(프로필·discovery·JWKS·토큰 클레임), `tests/test_mode3_demo_stack.mjs`(운반·고정·변경·변조 거절·하위호환), `tests/test_mode3_browser.mjs`(도구 페이지 — 무요청·Node 재계산 일치·지우기·백업; 프로필 카드). |

회로·컨트랙트·zkey·Snap 번들: **변경 없음**(1단계). Snap 재설치 불필요.

## 9. 보안·프라이버시 메모

- **IdP 가 보는 것**: `name` 한 칸(커밋먼트)과 세션 가명뿐. 속성·blind 는 도구 페이지의 localStorage 에만 있다(D8 — IdP 페이지의 JS 가 비밀을 만지지 않는다). IdP 는 `C_attr` 로 속성에 대해 아무것도 알 수 없다.
- **RP-hiding 유지**: 토큰에 `auid_s`·`arid_s`·`C_attr` 만 적힌다. IdP 는 `arid` 를 여전히 모른다.
- **토큰 재사용**: `sub`·`aud` 가 그 로그인의 증명 공개 입력에 묶이고 `exp` 10분이라 다른 세션·다른 RP 에 재제출할 수 없다. RP 는 토큰을 저장하지 않는다.
- **IdP 가 검증하지 않는 `name`**: 표준 IdP 의 사용자 편집 프로필과 같은 신뢰 수준. 엉뚱한 값은 RP 에 고정될 뿐이고 2단계 증명을 통과하지 못한다.
- **RP 간 연결성**(§3): `C_attr` 가 RP 마다 같아 두 RP 가 공모하면 같은 사용자임을 안다. 사용자 결정(D7)으로 수용. RP 별 값이 필요하면 §11.
- **도구 페이지의 비밀 보관**: localStorage 평문(web 모드의 금고와 달리 비밀번호 없음) — 같은 오리진(:5100)의 다른 페이지(지갑 페이지)가 읽을 수 있다. 데모 범위에서 수용; 필요하면 별도 오리진·금고(`lib/browser/secret_box.js`)로.
- **Google 경로(비범위)**: 외부 IdP 토큰의 `name` 은 통제할 수 없다. 후속.

## 10. 테스트·검증(1단계)

1. unit: `attrCommit` 결정성·blind 분리·형식 검사·도메인 상수.
2. IdP: 프로필 세션/형식/저장/삭제, discovery·JWKS(`d` 없음), 발급 `id_token` 이 JWKS 로 검증되고 `sub=auid_s`·`aud=arid_s`·`name=프로필`·`exp−iat=600`; 다른 aud 거절; 프로필을 비우면 `name` 없음.
3. 전 구간: 프로필 없음 → `attrCommit null`(토큰은 있음); C1 → 고정(세션 목록에도); C2 → `attrCommitChanged`; 비움 → C2 유지; 변조 토큰 → `bad_id_token`; 숫자 토큰 → 400; 토큰 없이 → 로그인되고 고정값 보임.
4. 브라우저: 도구 페이지가 정적 자원 외 요청 없이 커밋먼트를 만들고 Node 재계산과 일치, 빈 필수 칸 거절, 지우기·백업 복원·손상 백업 거절; `/user` 프로필 카드 저장·표시·비움.

## 11. 남는 질문·후속

- **RP 별 커밋먼트**(비연결성): 도구가 RP 별로 다른 blind 로 여러 커밋먼트를 보관하고, 사용자가 RP 마다 다른 값을 프로필에 넣는 운용(프로필이 한 칸이라 로그인 직전에 바꿔야 한다) vs. 토큰에 RP 별 칸을 두는 변형. 사용자 결정 대기.
- **IdP 최소 관여의 나머지(D5)**: 등록 때 지갑 공개키를 IdP 가 모르게 묶는 nonce 설계, 등록부·폐기 게시·RP 인증서·개봉을 IdP 밖의 별도 서버(ZDS)로 빼는 분리. 별도 스펙.
- 2단계 `pi_attr` 빌드는 사용자 승인 뒤(회로 컴파일·zkey 생성 시간).
- `name` 인코딩: 10진(최대 77자). 바꾸려면 `isAttrCommit` 과 도구 한 줄.
