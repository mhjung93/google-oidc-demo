# Mode 3 V11 — 그림(2026-10-12 Overall Flow · 덱 3~8장)에 코드를 맞추는 프로토콜 판 올리기

작성 2026-10-12. 상태: **구현 완료(결과 `results/mode3_v11_figure_protocol_20261013.md`)**. 브랜치 `feat/mode3-v11`(태그 `mode3-v10` = 78b2a1f 에서 분기). 근거: `documents/261012.pptx`(Overall Flow·Properties), `documents/261010_now.pptx` 3~8장(ID 변환·π_IdP·π_RP·π_s·토큰), 2026-10-12 대화의 결정 D1~D3·D7·D10·D15, 현행 코드 사실(`circuits/pi_cred.circom` `PiCred(32, 20)` 공개 입력 30개, `lib/mode3_credential.js`, `lib/mode3_issuance.js`, `cia.js`, `mode3_wallet_agent.js`, `mode3_rp.js`, `contracts/Mode3Wallet.sol`).

## 0. 한 줄 요약

사용자 가명 `auid = H(uid, salt)` 와 세션 가명 `auid_s = H(auid, rid, r_RP)`, `arid_s = H(rid, r_RP)` 를 도입하고, IdP 토큰이 `(auid_s, arid_s, H(C_u), H(C_s))` 를 덮으며, 세션 커밋먼트 `C_s` 가 `(pk_s, max_height, r_s)` 를 blind `r_RP` 로 묶고, 세션(토큰 발급)마다 π_IdP 를 제출한다. **속성 값은 사용자가 지갑에서 넣고 IdP 는 모른다**(V6 이전으로 복귀 — G5 "attribute privacy" 원래 뜻 복원). 추적은 trace_tag(2-of-2) 하나로 둔다. 모드를 새로 만들지 않고 Mode 3 의 판을 올린다(V11).

## 1. 결정

| # | 결정 | 내용 | 출처 |
|---|---|---|---|
| D1 | 추적은 trace_tag 로만 | auid_s·arid_s 는 세션 바인딩용. IdP 세션 기록에는 지금처럼 `(H(C_s), max_height, chain_id, allowAgent)` 만 — auid_s 를 남기지 않는다 | 사용자 2026-10-12 |
| D2 | π_IdP 는 세션마다 | 토큰 발급 요청마다 π_IdP(Groth16) 제출·검증 (그림 3). 로그인당 ≈ +0.45 s 를 수용 | 사용자 2026-10-12 (Q1) |
| D3 | 토큰에 auid_s·arid_s 포함 | IdP 는 값을 보되 저장하지 않는다(그림 3·4) | 사용자 2026-10-12 |
| D4 | auid 가 `cm_u` 를 대체 | 등록 때 지갑이 `auid = Poseidon(T_AUID, uid, s_u)` 제출. 등록부 리프 = `Poseidon(auid, H(C_u))`. `r_u`·`cm_u`·`RegistrationCommit` 삭제 | 기본값(§3.1) |
| D5 | `C_s = pk_s·G_PK + max_height·G_EXP + r_s·G_RS + r_RP·H` | arid 는 C_s 에서 빠지고 토큰의 arid_s 로; max_height(만료)·r_s(세션 nonce)가 들어감(2026-10-07 결정 "max_height 는 C_s 안") | 기본값(§3.2) |
| D6 | RP 챌린지 = `r_RP` + `r_s` | 둘 다 RP 가 뽑는 250비트 난수. r_RP 는 IdP 에 안 보임 | 덱 3장 |
| D7 | **auid_s 에 rid 포함** `auid_s = Poseidon(T_AUIDS, auid, arid, r_RP)` | 덱의 `H(auid, r_RP)` 에 rid 를 넣는다. 담합한 RP 둘(또는 낮은 엔트로피 구현)이 같은 r_RP 를 쓰면 같은 사용자의 auid_s 가 RP 간에 같아져 **RP 간 연결(G3 위반)** 이 생기는데, rid 가 들어가면 어떤 r_RP 에서도 `H(auid, rid_A, R) ≠ H(auid, rid_B, R)`. 메시지·흐름은 그림 그대로. IdP 는 r_RP 를 모르므로 계산 불가(RP 은닉 유지) | 사용자 2026-10-12 (Q2) |
| D8 | cert_s·pk_trace 유지 | 그림 2 에는 없지만 G6(피싱 차단)·태그 키라 로그인 요청에 그대로 둔다. 그림에는 각주 | 기본값 |
| D9 | `σ_{sk_s}(r_s)` 유지 | 로그인 때 세션키 서명. 회로 비용 0, 세션키 소유 증명 | 기본값 |
| D10 | π_IdP 는 Groth16 회로 `pi_idp` | 해시 관계(auid = H(uid, s_u), auid_s = H(auid, arid, r_RP))는 시그마 프로토콜로 못 하므로 두 번째 회로(§4). 지금의 π_u(시그마)를 대체 | 필연 + 사용자(Q1) |
| D11 | `/cia/user_cred` 를 `/cia/issue` 에 합침 | 그림 3 처럼 DA request 하나에 (C_u, C_s, π_IdP). 요청의 C_u 가 활성 C_u 와 다르면 IdP 가 등록부 슬롯을 갱신·게시한 뒤 토큰을 낸다(첫 로그인·속성 변경) | 기본값(§5.2, Q3) |
| D12 | 공개 입력 30 → 33, 끝에 추가 | `[30] auid_s [31] arid_s [32] r_s` — 기존 0~29 색인 유지(`PUB_INDEX`·AttrGate 꼬리 15워드·다이제스트 불변) | 기본값 |
| D13 | PPID = `Poseidon(uid, s_u, arid, chain_id)` | 덱 순서 H(uid, salt, rid, chain_id). 지금 `(uid, s_u, chainid, arid)` 에서 순서만 바뀜 — 계정 주소 전부 바뀜(어차피 팩토리 재배포) | 덱 3장 |
| D14 | 모드 4 로 분리하지 않음 | 같은 프로토콜의 판 올리기. V10 은 태그 `mode3-v10` 으로 보존 | 사용자 2026-10-12 |
| **D15** | **속성 값은 사용자가 넣고 IdP 는 모른다** | V6(2026-09-22 "속성 출처 = AA 기록")을 되돌린다. 지갑이 `profile` 을 들고 스펙 2 의 공개 스키마로 인코딩해 C_u 에 넣는다. IdP 는 C_u(커밋먼트)만 보고 속성 값·`profile` 을 받지도 저장하지도 않는다. π_IdP 는 uid·salt 관계만 증명(덱 6장 그대로). 관리자 속성 변경 라우트·UI 는 없어진다. **결과: 술어(나이·국가)는 "사용자가 주장한 값" 위의 증명**이다 — 값의 보증은 범위 밖(§10 후속: 속성 발급자). G5 는 원래 뜻("IdP 가 속성 값을 모른다")으로 돌아온다 | 사용자 2026-10-12 |
| D16 | IdP 는 max_height 를 π_IdP 공개 입력으로 본다 | 세션 기록(만료 정리·세션 폐기 거절)에 필요. RP·체인도 보는 값이라 비밀이 아님 | 기본값(Q4) |

## 2. 표기 (H = Poseidon, 덱 표기 ↔ 코드)

| 덱 | 코드 | 정의 |
|---|---|---|
| salt | `s_u` | 사용자만 아는 250비트 난수 |
| rid | `arid` | IdP 가 서비스 등록 때 배정한 서비스 식별자(cert_s 에 서명됨) |
| auid | `auid` | `Poseidon(T_AUID, uid, s_u)` — IdP DB `(uid, auid)`, 사용자마다 고정 |
| r_RP | `r_rp` | RP 가 세션마다 뽑는 250비트 난수(챌린지와 함께 전달), IdP 에 비공개 — auid_s·arid_s·C_s blind 에 쓴다 |
| auid_s | `auid_s` | `Poseidon(T_AUIDS, auid, arid, r_rp)` (D7) |
| arid_s | `arid_s` | `Poseidon(T_ARIDS, arid, r_rp)` |
| r_s | `r_s` | RP 챌린지(세션 nonce, 250비트). RP 가 1회 소비 |
| pk_s | `pk_i` | 세션 키(secp256k1 주소, 160비트) |
| expire | `max_height` | 지갑이 정한 만료 블록(그리드 양자화, 상한 L) |
| attributes | `attrs[6]` | 지갑의 `profile` 을 스펙 2 스키마로 인코딩한 64비트 6칸(D15 — 사용자가 넣음) |
| C_u | `C_u` | `uid·G_UID + s_u·G_SU + Σ_{k<6} a_k·G_ATTR[k] + blind_u·H` (식 불변) |
| C_s | `C_s` | `pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H` |
| Token σ_s | `sigma` | `EdDSA_IdP(Poseidon(D_V11, auid_s, arid_s, Cf_u, Cf_s, chain_id, allowAgent))`, `Cf_x = Poseidon(C_x.x, C_x.y)` |
| π_IdP | `pi_idp` | 세션마다 IdP 에 제출하는 Groth16 (§4) |
| π_RP | `pi_cred` V11 | 로그인 때 RP 에 제출 (§5.3) |
| π_s | — | π_RP 재사용(술어가 바뀌면 새 π_RP) — 심볼만 다르고 같은 증명 |
| trace_tag | `tag` | `ElGamal_{pk_trace}(Poseidon(uid, arid); ρ)`, ρ 는 증명마다 새로(불변) |
| PPID | `PPID` | `Poseidon(uid, s_u, arid, chain_id)` |

태그 상수(ASCII 빅엔디언 정수, 기존 `DOMAIN_*` 관례): `T_AUID = "MODE3AUID"`, `T_AUIDS = "MODE3AUIDS"`, `T_ARIDS = "MODE3ARIDS"`, `D_V11 = "MODE3CREDV11"`, `D_ISSUEREQ_V11 = "MODE3ISSUEREQV11"`, `D_REGISTER_V2 = "MODE3REGISTER2"`. 생성원: `G_PK = G_pk_i`(기존), `G_EXP`·`G_RS` 는 새 base point(`getBasePoint('blake', 11·12)` — attr5 선례), `H = G_blind`(기존). 기존 `G_arid` 는 C_s 에서 빠진다(상수는 남겨 두되 미사용).

## 3. 등록·속성·세션 난수

### 3.1 등록 (`POST /cia/register`)
- 지갑: `s_u`, `sk_u`(등록 키) 생성 → `auid = Poseidon(T_AUID, uid, s_u)`.
- 본문 `{ uid, pwd, auid, pk_u, sig_reg }`, `sig_reg = EdDSA_{sk_u}(Poseidon(D_REGISTER_V2, uid, auid))`.
- IdP: 데모 계정 인증 → `accounts[uid] = { pk_u, auid, slot, creds:[], sessions:[] }`. **`attrs`·`profile` 필드는 없다(D15).** 같은 uid 의 두 번째 등록은 409(불변성). `cm_u` 필드는 없어진다.
- auid 는 salt 의 엔트로피(250비트)로 가려져 uid 외의 정보를 주지 않는다. IdP 가 아는 것은 지금(`cm_u`)과 같다.

### 3.2 세션 난수
- RP `/api/mode3/challenge` → `{ r_s, r_rp, expiresAt, factoryAddress, attrGateAddress }`. 둘 다 250비트 난수, 챌린지 수명 안에서만 유효하고 `r_s` 는 1회 소비.
- 지갑은 `r_rp` 를 그대로 auid_s·arid_s·C_s blind 에 쓴다. RP 는 자기 `r_rp` 로 `arid_s` 를 재계산해 대조한다(토큰이 이 세션용인지 확인).
- `C_s` 의 blind 가 `r_rp` 이므로 RP 는 `C_s` 의 모든 열림값(`pk_i`, `max_height`, `r_s`, `r_rp`)을 안다 — RP 가 C_s 를 직접 다시 계산해 공개 입력과 대조할 수도 있다(π_RP 안의 등식과 중복 — 심층 방어).
- **RP 간 연결 방어(D7)**: auid_s 에 arid 가 들어가므로 두 RP 가 같은 `r_rp` 를 써도 같은 사용자의 auid_s 가 다르다. RP 가 r_rp 를 재사용하면 **그 RP 안에서** 세션끼리 auid_s 가 같아지지만, 그 RP 는 PPID 로 이미 같은 사용자를 아는 터라 새로 새는 것이 없다.

### 3.3 속성 (D15 — 사용자 소유)
- 지갑 상태에 `profile`(스펙 2 의 이름값: `{ birthYear, country, extra1, extra2 }`)을 둔다. 등록·로그인 전에 지갑 페이지(또는 Snap 대화상자)에서 입력·수정한다. 인코딩은 스펙 2 의 `encodeProfile`(공개 스키마 `zkd-attrs` v1 — int/enum/string/unused, 64비트)을 **지갑이** 수행해 `attrs[6]` 을 만든다.
- 스키마는 지금처럼 IdP 가 `GET /cia/attr_schema` 로 공개한다(인코딩 규칙의 공통 기준일 뿐 값과 무관). RP 정책(`MODE3_ALLOWED_COUNTRIES`)·AttrGate 는 그대로.
- **IdP 는 속성 값을 받지 않는다**: `/cia/issue` 본문에 attrs 가 없고, π_IdP 의 공개 입력에도 없다(§4). `/cia/attrs`·관리자 `POST /cia/accounts/:uid/attrs`·관리자 페이지의 속성 열은 삭제한다.
- 속성 변경 = 지갑이 `profile` 을 바꾸고 새 `blind_u` 로 **새 C_u** 를 만들어 다음 `/cia/issue` 에 실음 → IdP 는 (D11) 활성 자격증명을 은퇴하고 새 리프를 게시한다. 사용자 주도이므로 "관리자가 속성을 바꿔 자격증명을 물리는" 각본(11·F5)은 없어진다.
- **결과와 한계**: 술어는 "사용자가 주장한 값" 위의 증명이다. 거래소 데모의 "나이 ≥ 19" 는 메커니즘(선택 공개·집합 소속·온체인 검사) 시연이지 값의 진위 보증이 아니다 — 런북·덱·논문에 그렇게 적는다. 값 보증은 §10 의 속성 발급자(AA ≠ IdP)로 미룬다.

## 4. π_IdP — 새 회로 `circuits/pi_idp.circom`

세션(토큰 발급)마다. IdP 가 서명하기 전에 **uid·salt 관계와 세션 바인딩**만 확인한다(덱 6장 (1)(2) + D3 의 auid_s 정형성). 속성은 보지 않는다(D15).

- 비공개: `s_u, blind_u, attrs[6], arid, r_rp, pk_i, r_s` — **arid·attrs 는 IdP 에 비공개**. IdP 는 "어떤 arid·r_rp·속성에 대해 정형" 이라는 것만 안다.
- 공개: `uid, auid, auid_s, C_u.x, C_u.y, C_s.x, C_s.y, max_height`
- 제약:
  1. `C_u = uid·G_UID + s_u·G_SU + Σ attrs[k]·G_ATTR[k] + blind_u·H` (CommitUser 재사용; attrs 는 64비트 범위만 — 값은 자유)
  2. `auid = Poseidon(T_AUID, uid, s_u)`
  3. `auid_s = Poseidon(T_AUIDS, auid, arid, r_rp)`
  4. `C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H` (같은 `r_rp` — auid_s 와 C_s 의 결합), `pk_i` 160비트, `max_height` 64비트, `r_s`·`r_rp` 250비트
- IdP 쪽 검사: `uid` 는 sig_u 의 계정, `auid` 는 DB 값, `Poseidon(C_u)` 는 활성 Cf_u 이거나 새 C_u(§5.2), `max_height < 2^64`. `arid_s` 는 IdP 가 검사하지 않는다(rid 를 모름) — RP 가 π_RP 로 본다.
- 추정 규모: CommitUser(약 7k) + C_s(약 5k) + Poseidon 2 → **약 13k 제약, 증명 ≈ 0.45 s, 검증 ≈ 10 ms**(pi_cred 34,934 제약 = 1.27 s 비례).

## 5. 세션 흐름 (그림 1~7)

### 5.1 1·2 — 로그인 시작·Auth request
RP → 지갑: `{ arid, origin, cert_s, pk_trace, r_s, r_rp, allowAgent, factoryAddress, attrGateAddress, disclose, set }`. 지갑은 cert_s 를 pk_CIA 로 검증하고 오리진을 대조한다(불변).

### 5.2 3·4 — DA request / 토큰 (`POST /cia/issue` V11)
본문 `{ uid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height, proof_idp, sig_u }`,
`sig_u = EdDSA_{sk_u}(Poseidon(D_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height))`.
IdP 검사 순서(코드 순서, `cia.js`): 형식 → `max_height < 2^64` → 계정·disabled → chainid 허용 → C_u·C_s 부분군 → sig_u → **π_IdP 검증**(공개 입력: uid, 계정의 auid, auid_s, C_u_pt, C_s_pt, max_height) → 체인 생존 → disabled 재확인 →
- `Cf_u = Poseidon(C_u_pt)` 가 활성 자격증명과 같으면 그대로; 다르면(첫 로그인·사용자의 속성 변경 뒤) **활성 자격증명 은퇴 → `creds` 에 추가 → `setSlot(uid, Poseidon(auid, Cf_u))` → persist → 즉시 게시**(지금 `/cia/user_cred` 가 하던 일) →
- 서명 `sigma = EdDSA_IdP(Poseidon(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent))` →
- 세션 기록 `{ Cf_s, max_height, chainid, allowAgent, issuedAt }`(auid_s·arid_s 는 **기록하지 않음**, D1) →
- 응답 `{ Cf_u, Cf_s, chainid, allowAgent, sigma, pk_CIA, slot, regRoot, epoch, published }`.
`/cia/user_cred`·`/cia/attrs`·`/cia/accounts/:uid/attrs` 라우트는 삭제한다(D11·D15). `/cia/slot` 은 그대로.

### 5.3 5·6 — π_RP (`pi_cred` V11) 와 로그인
공개 입력 33개 — 기존 `[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10,11] pk_trace [12..14] tag [15] disc_mask [16..21] disc_lo [22..27] disc_hi [28] set_sel [29] set_root` + **`[30] auid_s [31] arid_s [32] r_s`**.
비공개: `uid, s_u, blind_u, r_rp, attrs[6], r(태그 난수), S, R8x, R8y, s_*(폐기 트리 32), reg_*(등록부 20), set_index, set_path[8]`. (`r_u`·`blind_s` 삭제.)
제약(덱 7장 (1)~(7) 대응):
1. 토큰: `EdDSA_IdP` over `Poseidon(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent)`, `max_height` 64비트, `allowAgent ∈ {0,1}`
2. ID 정확성: `auid = Poseidon(T_AUID, uid, s_u)`, `auid_s === Poseidon(T_AUIDS, auid, arid, r_rp)`, `arid_s === Poseidon(T_ARIDS, arid, r_rp)` (arid 는 공개 입력 [1])
3. `PPID === Poseidon(uid, s_u, arid, chainid)`
4. 선택 공개·집합 소속(불변) — 사용자가 넣은 attrs 위에서
5. 같은 `r_rp`: 2 의 두 해시와 `C_s` 의 blind 가 하나의 비공개 `r_rp`
6. 등록부: `Poseidon(auid, Cf_u) ∈ Tree(regRoot)`(깊이 20) · 폐기: `Poseidon(5, Cf_s) ∉ Tree(revRoot)`(IMT 32)
7. `C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H` 로 `r_s`(공개)와 `max_height`(공개) 가 C_s 에 묶임 — 재전송 방지(RP 가 r_s 를 1회 소비)
8. trace_tag(불변): `c1 = ρ·B`, `c2 = Poseidon(uid, arid) + Poseidon(ρ·pk_trace)`, `ρ ≠ 0`

로그인 본문(지갑 → RP 페이지 → RP): `{ r_s, proof, publicSignals(33), sig = σ_{sk_s}(r_s), require? }` — 지금과 같은 모양.
RP `verifyLogin` 추가 검사(기존 a~g 사이, d 뒤): `pub[32] === 소비한 r_s`, `pub[31] === Poseidon(T_ARIDS, arid, r_rp)`(그 r_s 와 함께 발급한 r_rp 로 — 챌린지 기록에 r_rp 를 둔다), `pub[30]`(auid_s)은 형식만. 세션 기록 `{ PPID, pk_i, max_height, allowAgent, root, regRoot, disclosure, auid_s, arid_s, at }` — 덱의 RP DB `(auid_s, arid_s, PPID)`.

### 5.4 7 — 트랜잭션
불변: `execute(payload, σ_tx, π, pub[33])`. `σ_tx` 다이제스트 필드와 꼬리 15워드(`pub[15..29]`)는 그대로. 술어가 바뀌면 새 π_RP(지금 규칙). 재검증(`/api/mode3/revalidate`)은 캐시 π 로 — `r_s` 가 세션 식별자라 그대로 맞는다.

## 6. 컨트랙트·검증기

- `PiCredVerifier` 재생성(공개 입력 33). `Mode3Wallet.execute(..., uint[33] pub)`, `_checkStatement` 는 색인 0~29 검사 그대로(30~32 는 온체인에서 보지 않음 — RP 가 본다). 꼬리·다이제스트 불변. `Mode3WalletFactory`·`AttrGate` 소스 불변(재배포는 필요 — 검증기 주소·PPID 식 변경).
- `pi_idp` 는 온체인에 가지 않는다(IdP 만 검증).

## 7. 상태·이행·화면

- **CIA 상태 v12**: `accounts[uid].auid`(필수), `cm_u`·`attrs`·`profile` 삭제, 등록부 리프 식 변경. `attrSchemaHash`(스펙 2)는 유지(스키마 공개는 계속). **v11 이하 상태 파일은 이행하지 않고 기동 거부**("V11 은 새로 시작 — 재시연 세트"). 이유: 옛 계정의 auid 를 IdP 가 알 수 없고(지갑만 계산 가능), 리프 식·PPID 식이 바뀌어 체인도 새로 배포해야 한다. V5·V9 때와 같은 "로그 재배포 → 상태 파일 새로" 절차. `DEMO_ACCOUNTS` 는 `{ password, uid }` 만.
- **지갑 상태 v9**: `registration` 에서 `r_u`·`cm_u` 삭제, `auid`·`profile`(사용자 입력, 기본값은 데모 testuser `{birthYear:'1990', country:'KR'}`)·`attrs`(인코딩) 추가; `sessions[r_s]` 에 `r_rp`, `auid_s`, `arid_s`; `credential` 에 `sigma`·`auid_s`·`arid_s`. 옛 파일은 등록만 유지하고(auid 는 s_u 로 재계산, attrs 는 그대로) 세션은 비운다(기존 관례). `/wallet/attrs/sync` 삭제, **`PUT /wallet/profile { profile }`**(스키마 검증 → attrs 재인코딩 → 다음 로그인에 새 C_u) 추가.
- **Snap**: `registration { uid, s_u, sk_u, attrs }`(r_u 삭제), 증인 `{ uid, s_u, sk_u, attrs, userCred }`. 등록 대화상자에 속성 입력 단계(또는 지갑 페이지에서 입력 후 `storeRegistration` 으로 전달 — 구현 계획에서 결정). `syncAttrs` RPC 는 "사용자 변경 반영" 뜻으로 유지.
- **화면**: 지갑 (내 신원) 카드의 속성 칸이 **편집 가능**(스키마 타입별: 숫자·국가 선택·문자열)해지고 "저장 → 다음 로그인에 반영"; 관리자 페이지의 속성 열·저장 버튼 삭제; RP 페이지 그대로. `strings.js` 에서 "AA 기록"·"관리자가 바꾼다" 문구 제거.
- **런북·각본**: 각본 1 "속성은 AA 기록값" → "지갑에 넣은 값", 11 "관리자 속성 변경" → "지갑에서 속성 변경 → 새 C_u·같은 PPID", F5 "관리자의 잘못된 속성" → "지갑의 잘못된 속성(스키마 검증 거절)". "속성과 선택 공개" 절의 출처 문단을 D15 로.

## 8. 비용

| 항목 | V10 | V11(추정) | V11 실측 | 근거 |
|---|---|---|---|---|
| π_RP 제약 | 34,934 | ≈ 35,000 ± 1,500 | **33,909** | −RegistrationCommit(스칼라곱 2) +C_s 스칼라곱 2(64·250비트) +Poseidon 4. 실측은 추정 범위 하단(−1,025) |
| π_RP 공개 입력 | 30 | 33 | **33** | D12 |
| π_RP 증명 / 검증 | 1,271 / 11.3 ms | ≈ 1,300 / 12 ms | **1,168.2 / 9.3 ms** | 제약 비례(`scripts/bench_pi_cred.mjs`, 10회 중앙값) |
| π_IdP 제약 | (없음 — V10 은 π_u) | ≈ 13,000(§4) | **6,325** | CommitUser 3,537 + CommitSessionV11 2,236 + Poseidon(auid·auid_s) — 추정의 절반 |
| π_IdP 공개 입력 | — | 8 | **8** | §4 |
| π_IdP 증명 / 검증 | 80 / 99 ms(시그마 π_u) | **≈ 450 / 10 ms** | **292.0 / 13.2 ms** | §4(`scripts/bench_pi_idp.mjs`, 10회 중앙값) |
| 세션 발급(IdP 왕복) | 134 ms | ≈ 150 ms + π_IdP 검증 | **467 ms**(중앙값, 448–1582) | `scripts/bench_mode3_onchain.mjs` 의 `issueMs` — `issueSession` 전체(지갑 쪽 π_IdP 생성 ≈292ms 포함) + `/cia/issue` 왕복(sig_u·π_IdP 검증·서명). V10 기준 134ms + π_IdP 증명 292ms + π_IdP 검증 13ms ≈ 440ms 로 467ms 가 거의 설명된다 |
| 로그인 왕복 | 1,626 ms | **≈ 2,100 ms** | **1,837 ms**(중앙값, 1808–7087) | `scripts/bench_mode3_onchain.mjs` 의 로그인 전체 왕복 — π_IdP 생성이 더해짐. 첫 로그인(신규 발급 + 등록부 게시 대기 포함)은 7,087 ms |
| execute gas | 455,947 | ≈ 470,000 | **477,220** | 같은 스크립트·같은 조건(`scripts/bench_mode3_onchain.mjs`, mask=0·캐시 π·value=0)으로 비교한 값. +21,273(+4.67%) — 공개 입력 +3(검증기 ≈20,000 + calldata ≈1,500)로 거의 전부 설명된다. `test/Mode3Wallet.test.mjs` 자체 측정(525,655)은 **다른 조건**(갓 배포된 지갑의 첫 execute + 한 번도 안 건드린 주소로 value 0.1 ETH 전송 — EVM 새 계정 생성 비용 ≈25,000 포함)이라 이 행과 직접 비교하지 않는다 — 결과 파일의 "execute gas 증가 분석" 절 참고 |
| zkey | 22.3 MB | ≈ 22.5 MB + ≈ 8 MB(pi_idp) | **22.1 MB + 4.0 MB(pi_idp)** | pi_idp 는 제약 수가 추정의 절반이라 zkey 도 추정의 절반 수준 |

실측: `results/mode3_v11_figure_protocol_20261013.md`(위 표에 반영).

## 9. 보안·프라이버시 메모

- **G5 복원(D15)**: IdP 는 속성 값을 모른다(C_u 는 Pedersen 은닉, π_IdP 의 공개 입력에 속성 없음). RP 는 공개한 술어만 안다(G5a). AA 측 "익명 집합 축소"(V6 §7 G4′ 약화 — AA 가 모든 값을 알아 술어 만족 집합을 셈)는 **사라진다**.
- **대가**: 속성 값에 보증이 없다. 거래소가 "나이 ≥ 19" 를 받아들이는 근거는 "이 사용자가 그렇게 주장했고 그 주장이 그 자격증명에 고정돼 있다" 까지다. 논문·덱에 한계로 적고, 보증은 §10 의 속성 발급자로.
- **IdP 가 보는 것**: uid, auid(고정), auid_s·arid_s(세션마다, 저장 안 함 — D1), H(C_u), H(C_s), max_height, chain_id, allowAgent. r_rp 를 모르므로 arid_s 로 서비스를 못 알아보고(G4), auid_s 로 세션을 사용자와 묶는 것은 uid 를 이미 알므로 새 정보가 아니다.
- **설계 노출 — IdP 단독으로도 연결 가능(후퇴, 컨트롤러 판정: 설계는 바꾸지 않는다).** π_RP 공개 입력 `[30] auid_s`·`[31] arid_s`
  는 `/wallet/tx` → `Mode3Wallet.execute(..., uint[33] pub)` 의 calldata 에 그대로 올라가 체인을 읽는 누구나 본다. IdP 는
  `/cia/issue` 에서 같은 `auid_s`·`arid_s` 를 요청 본문으로 받는다(D3). **요청 본문을 남기는 honest-but-curious IdP 라면**, RP
  협력이나 trace_tag 개봉 없이도 그 `auid_s` 를 자기 로그와 체인의 calldata 에서 맞춰 uid ↔ PPID 계정(`pub[0]`) ↔ 서비스
  (`pub[1]` arid) ↔ 트랜잭션을 이을 수 있다. "IdP 는 auid_s·arid_s 를 기록하지 않는다"(D1)는 **암호학적 보장이 아니라 신뢰
  가정**이다. **V10 대비 후퇴**다 — V10 에서 IdP 가 보는 값(Cf_s 등)은 공개 입력에 그대로 없어 이런 결정적 연결이 없었다.
  완화 후보(둘 다 미적용, **사용자 결정 대기**): ① 운영으로 IdP 의 요청 본문 비보존(D1)을 정책·감사로 강제한다. ② 설계 대안으로
  auid_s·arid_s 를 비공개 입력으로 돌리고 RP 대조값은 `Poseidon(r_rp)` 류의 IdP 가 재계산할 수 없는 값만 공개한다 — 회로·산출물·
  컨트랙트 재생성이 필요하다.
- **RP 가 보는 것**: 지금과 같음 + auid_s·arid_s(세션 바인딩). RP 간 연결은 D7 로 막힘.
- **담합(IdP + RP)**: RP 가 r_rp 를 주면 IdP 가 `H(auid, arid, r_rp)` 로 auid_s 를 맞춰 uid ↔ PPID 를 잇는다 — trace_tag 개봉과 같은 권한(의도된 추적성, D1 은 "경로를 그걸로 두지 않는다" 는 뜻).
- **r_rp 재사용(한 RP 안)**: 새는 것 없음(§3.2). **r_rp 를 IdP 가 알게 되면** arid_s 로 RP 를 알아본다 — RP 가 IdP 에 r_rp 를 넘기지 않는 것이 G4 의 전제(지금의 "C_s 안의 arid" 와 같은 수준).

## 10. 범위 밖·후속

- **속성 발급자(AA ≠ IdP)**: 별도 기관이 `C_attr` 를 서명하고 `C_u = C_id + C_attr`, π_RP 가 그 서명을 검증 — 값 보증을 되살리는 길. 별도 스펙.
- 거울 라이트 클라이언트, salt 시드 파생, 스키마 해시 서명 바인딩(스펙 2 후속), 물리적 4슬롯, VRF 키(두 번째 등록 탐지), 등록부 증분 캐시.

## 11. 테스트·검증 (계획에서 작업으로 풀 것)

- 단위: auid·auid_s·arid_s·PPID 계산기, 토큰 메시지, `pi_idp` 증인(양성·음성: 다른 s_u, 다른 r_rp, auid 불일치; 속성은 자유값이어야 통과), `pi_cred` V11 증인(공개 입력 33, (2)(5)(7) 음성, 같은 r_rp 로 다른 arid 의 auid_s 가 다름).
- 컨트랙트: `execute(uint[33])`, 다이제스트·꼬리 불변 확인, 팩토리·AttrGate 재배포.
- chain: 등록(auid, 속성 없음)·발급(π_IdP, C_u 교체 경로)·로그인(r_rp/arid_s 검사, 재전송 r_s 거절)·재검증·세션 폐기·개봉·**지갑 속성 변경 → 새 C_u·같은 PPID**·등록부 바꿔치기·거울 지연·접수증 — 기존 각본 0~14 와 실패 각본 F1~F6(F5 는 지갑 쪽으로) 전부, 데모 벡터 갱신. IdP 상태 파일에 속성이 없음을 단언.
- browser·snap: 등록(r_u 삭제·속성 입력)·로그인·tx·동의 창.
- 벤치: `bench_pi_cred.mjs` + 새 `bench_pi_idp.mjs`, `bench_mode3_onchain.mjs` → `results/mode3_v11_*.md`.
- 마지막에 `tests/test_mode3_demo_full.mjs`.

## 12. 덱·그림에 반영할 것(코드와 무관)

- 3장 `auid_s = H(auid, rid, r_RP)`, 4장 (2) 같은 식. 11장 "가입 때 IdP가 확인·기록" → "사용자가 지갑에 넣음(IdP 는 모름)". 2페이지 G5 → G5a(RP 최소 공개)/G5b(IdP: 값도 사용처도 모름). 6장 π_IdP 에 세션 바인딩(auid_s·C_s 의 r_RP) 한 줄. 그림 2 에 cert_s·pk_trace 각주, 7 에 "π_s = π_RP 재사용", RCL 체인 화살표.

## 13. 남는 질문

- **속성 값의 보증 — 열린 문제로 남긴다**(사용자 2026-10-12: "속성값에 대한 보장은 다시 문제로 남겨두고 일단은 넘어가도록 하자"). V11 은 사용자가 넣은 값 위에서 술어를 증명하고(D15), 보증 주체(속성 발급자 AA ≠ IdP 등)는 §10 의 후속 스펙에서 다룬다. 런북·덱·논문에 "값은 사용자 주장" 임을 적는다.
- 그 밖에는 없음 — Q1(π_IdP 세션마다)·Q2(auid_s 에 rid)·Q3(user_cred 흡수, 기본값)·Q4(max_height 공개 입력, 기본값) 결정됨. 기본값 D4·D5·D6·D8·D9·D11·D12·D16 에 이견이 있으면 번호로.
