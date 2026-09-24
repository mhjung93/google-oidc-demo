# Mode 3 — 세션 폐기(V8) 설계: RCL 세션 리프 + 회로 두 번째 비멤버십

2026-09-24. 자격증명 이중 구조(2026-09-21 §9-2)에서 "폐기 = 사용자의 모든 세션"으로 뺐던 세션 단위 폐기를 되살린다. 결정(2026-09-24):
온·오프체인 모두 효력, 폐기 주체는 **사용자(지갑) + AA 운영자**, 방식은 RCL 에 세션 리프를 넣고 회로가 비멤버십을 하나 더 증명하는 것(A안).
RCL 을 사용자별 슬롯(latest valid/revoked)으로 바꾸는 안은 보류 — 발급이 체인 위로 올라가고 root 가 발급마다 바뀌어 V5 의 주장(발급은 체인 밖, root 는
폐기 때만)을 잃는다. 온체인 즉시 차단(계정 컨트랙트 세션키 블랙리스트, B안)은 후속으로 남긴다.

## 0. 결정 요약

| 결정 | 내용 | 이유 |
|---|---|---|
| 리프 | `Poseidon(TAG_MODE3_SESSION = 5, Cf_s)`, 사용자 리프 `Poseidon(4, Cf_u)` 와 **같은 IMT** | 서비스·컨트랙트가 root 하나만 보면 되고, 태그로 도메인이 갈린다 |
| AA 세션 기록 | 발급 때 `{Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt}` 을 사용자별로 기록. **arid·pk_i 는 여전히 C_s 안(못 봄)** | 폐기할 세션을 지정하려면 AA 가 Cf_s 를 알아야 한다. 발급 때 이미 본 값이라 새로 아는 것은 없다 |
| 누가 | 사용자: 지갑이 `sk_u` 서명으로 자기 세션의 Cf_s 지정. 운영자: 관리자 시크릿 + 관리자 페이지 | 서비스는 Cf_s 를 모른다(주지 않는다) |
| 효력 | 다음 게시(또는 하트비트) 뒤. 만료된 세션은 리프를 넣지 않는다(409 `expired`) | 만료가 이미 막는다 — 리프 낭비 금지 |
| 회로 | 비멤버십 2개, **공개 입력 25 그대로**(같은 root) | 서비스·컨트랙트 무변경. 검증자 재생성 → 팩토리 재배포는 불가피 |
| 트리 성장 | 폐기된 세션 리프는 만료 뒤 죽은 리프 — 재기준화로 접는 것은 **후속**(원칙만 적는다) | 지금 `imt_v2.rebaseline` 미사용 |

## 1. 무엇이 달라지는가 (V7 → V8)

| | V7 | V8 |
|---|---|---|
| 폐기 단위 | 사용자(C_u) | 사용자 + 세션(C_s) |
| RCL 리프 종류 | `Poseidon(4, Cf_u)` | + `Poseidon(5, Cf_s)` |
| AA 상태 | 세션 기록 없음(v7) | `accounts[uid].sessions[]` (v8) |
| `/cia/revoke` scope | `account`, `credential` | + `session`(Cf_s 지정) |
| 회로 비공개 입력 | 비멤버십 증인 1벌 | 2벌(`s_*`) |
| 제약 | 27,329 | ≈34k(예상 — `IMTNonMembershipV2(32)` ≈ 6.6k; 실측으로 갱신) |
| 지갑 폐기 사유 | `revoked` | `revoked`(계정/자격증명) / **`revoked_session`**(그 세션만) |
| 서비스·컨트랙트 | — | 변경 없음(검증자 컨트랙트만 재생성) |

## 2. AA (`cia.js`, `lib/mode3_cia_state.js`)

### 2.1 상태 v8
`accounts[uid].sessions: [{ Cf_s: string, max_height: string, chainid: string, allowAgent: '0'|'1', issuedAt: ISO, revokedAt: ISO|null }]`.
마이그레이션 v7→v8: `sessions = []`(옛 세션은 기록이 없으므로 폐기 불가 — 만료로만 끝난다. 문서화).
`/cia/issue` 성공 응답 직전에 push. 하트비트마다 정리: 체인별 head(`CIA_CHAIN_RPCS` 로 이미 읽는다)보다 `max_height` 가 작은 기록 삭제(폐기 여부 무관 — 리프는 남는다, §6).

### 2.2 `/cia/revoke scope=session`
- 본문 `{ uid, scope:'session', Cf_s, sig_u?: {R8x,R8y,S}, nonce? }  — 필드명은 `/cia/attrs` 와 같이 `sig_u`·`nonce`(10진)`.
- **인증 두 갈래**: (a) 관리자 시크릿(`requireAdmin`) — 지금 `/cia/revoke` 와 같은 헤더; (b) 사용자 — `sig` 가 `Poseidon(DOMAIN_MODE3_REVOKESESS, uid, Cf_s, nonce)` 위 `sk_u`(EdDSA-Poseidon, `acct.pk_u`) 서명. `DOMAIN_MODE3_REVOKESESS` = ASCII "MODE3REVOKESESS" 의 정수(`lib/mode3_issuance.js` 의 다른 도메인 상수와 같은 방식). nonce 는 지갑 난수(신선도 검사 없음 — `/cia/attrs` 와 같은 규칙; 재생해도 같은 세션을 다시 폐기할 뿐 멱등).
  라우트: 관리자 헤더가 없으면 `sig` 필수. 둘 다 없으면 401.
- 처리: 기록에서 `Cf_s` 찾기 → 없으면 404 `unknown_session`; `revokedAt` 이미 있으면 200 `{inserted:false}`(멱등); 해당 체인 head ≥ `max_height` 면 409 `expired`; 아니면 `leaf = Poseidon(5, Cf_s)` 를 트리 삽입(`pending` 으로 다음 게시), `revokedAt = now`, `persist()`. 응답 `{ inserted, leaf, root, pending }`.
- `scope=account`(계정 전체)는 그대로 — 사용자 리프 하나로 전 세션이 죽으므로 세션 리프를 따로 넣지 않는다.

### 2.3 관리자 페이지 (`mode3/cia_admin.html`)
계정 행에 "세션 (N)" 펼침: `Cf_s` 앞 10자리, chainid, max_height, allowAgent, 발급 시각, 상태(활성/폐기됨/만료) + "폐기" 버튼(→ `/cia/revoke scope=session`, 관리자 시크릿). 조회 API `GET /cia/admin/sessions?uid=`(requireAdmin) 추가. 개봉 결과와 연결하지 않는다(개봉은 uid 만 돌려준다 — 그대로).

## 3. 회로 V8 (`circuits/pi_cred.circom`)

```
// 비공개 입력 추가 — 세션 리프 비멤버십 증인
signal input s_lowValue; signal input s_lowNextIndex; signal input s_lowNextValue;
signal input s_pathElements[depth]; signal input s_pathIndices[depth];
// ④′ 세션 비멤버십 (④ 뒤)
var TAG_MODE3_SESSION = 5;
component sLeaf = Poseidon(2); sLeaf.inputs[0] <== TAG_MODE3_SESSION; sLeaf.inputs[1] <== Cf_s;
component nmS = IMTNonMembershipV2(depth); nmS.target <== sLeaf.out; (증인 배선) nmS.root <== revRoot;
```
공개 입력·`component main` 불변(25개). `Cf_s` 는 이미 ② 에서 공개 `arid`·`pk_i` 로 재계산한 값 — 증명자가 다른 Cf_s 를 넣을 수 없다.
`lib/mode3_revocation.js`: `TAG_MODE3_SESSION = 5n`, `sessionLeaf(Cf_s)`.

## 4. 지갑 (`lib/mode3_wallet.js`, `mode3_wallet_agent.js`, `mode3/wallet.html`, Snap)

- `buildCredentialProof`: `tree.getNonMembershipWitness(await sessionLeaf(Cf_s))` 를 하나 더 만들어 `s_*` 입력으로. 세션 리프가 트리에 있으면 `"is a member"` 로 던진다 — 호출자가 사용자 리프와 구분한다: `proveSession` 은 먼저 `tree.has(userLeaf)` → `revoked`, 다음 `tree.has(sessionLeaf)` → **`revoked_session`**.
- 에이전트: `revoked_session` 이면 **그 세션만** 삭제(`state.sessions[rsKey]`, 캐시), 403 `{ reason:'revoked_session' }`. 다른 세션·C_u 는 그대로. 재로그인은 새 C_s 로 즉시 가능.
- `POST /wallet/session/revoke { r_s }`(같은 오리진, `{confirm:true}` 없음 — 파괴적이지 않음): 세션의 `credential.Cf_s` 로 `sig` 를 만들어 `/cia/revoke scope=session` 호출. file 모드는 파일의 `sk_u`, snap 모드는 Snap RPC `signRevokeSession { Cf_s, nonce }`(동의 창: "이 세션(서비스 arid, 발급 시각)을 폐기합니다" 예/아니오) 로 서명을 받는다. 성공하면 로컬 세션도 지운다(게시 전이라도 지갑은 더 쓰지 않는다).
  **정정(2026-09-24 구현)**: Snap 에는 Poseidon 이 없어 서명을 만들 수 없다 — Snap RPC 는 동의만 받는 `consentRevokeSession { arid, issuedAt, maxHeight }` 이고, 서명은 에이전트가 그 세션의 메모리 증인 `sk_u` 로 한다(V7 까지의 다른 서명들과 같은 자리). 증인이 없으면 409 `needs_consent`.
- 지갑 페이지: 세션 목록 각 행에 "이 세션 폐기" 버튼. 결과 표시.
- 캐시 키·트리 동기화 불변(리프 종류가 늘어도 델타 동기화 동일).

## 5. 서비스(RP)

변경 없음. `revalidate` 가 지갑에서 `revoked_session` 을 받으면 `revoked` 와 같은 분기(세션 삭제) — `mode3/rp.html` 의 `if (wb.reason === 'revoked')` 에 `|| 'revoked_session'`.

## 6. 트리 성장과 재기준화(원칙, 구현은 후속)

폐기된 세션 리프는 `max_height` 를 지나면 죽은 리프다(만료가 막는다). AA 는 세션 기록에 `max_height` 를 가지므로 재기준화 때 `max_height < 모든 체인 head` 인 세션 리프를 제외한 새 트리를 만들 수 있다 — 트리 크기 ≈ 활성 폐기 세션 + 사용자 폐기 수. 이 spec 은 리프를 접지 않는다(`imt_v2.rebaseline` 미사용 그대로). 데모 규모에서는 문제없음. 논문 VII 한계 절에 한 줄.

## 7. 프라이버시·보안 메모

- AA 가 새로 아는 것은 없다(Cf_s·max_height·chainid·allowAgent 는 발급 때 본 값). 남는 것은 **상태**: 사용자별 세션 수·발급 시각. 서비스·pk_i 는 여전히 모른다(G4 유지).
- 게시된 리프 수로 "세션 폐기가 일어났다"는 공개된다. 사용자 리프와 세션 리프는 둘 다 Poseidon 출력이라 관찰자는 구분 못 한다.
- 사용자 폐기 요청 인증은 `sk_u`(등록 키). 비밀번호는 지금처럼 등록·계정 자기 폐기에만.
- 세션 폐기는 게시 뒤 효력 — 그 사이 온체인 실행은 막지 못한다(B안 후속). 문서·논문에 명시.
- 회로: `Cf_s` 는 공개 `arid`·`pk_i` 로 재계산되므로(②) 세션 리프를 피해 다른 Cf_s 로 증명할 수 없다.

## 8. 빌드·측정·문서

`bash scripts/build_mode3_circuit.sh pot21_final.ptau` → 검증자 재생성 → 팩토리·AttrGate 재배포(계정 주소 바뀜 — `docs/MODE3_DEMO.md` 경고 그대로). 재측정 `results/mode3_session_revocation_20260924.md`: 제약, π_rp ms, 로그인 왕복, execute gas(검증자 바뀜). `docs/MODE3_DEMO.md`: `/cia/revoke scope=session`, `/wallet/session/revoke`, 오류 사유 `revoked_session`·`unknown_session`·`expired`, 상태 v8 마이그레이션 주의(옛 세션은 폐기 불가), 시나리오 표에 "세션 하나 폐기 → 그 세션만 죽고 다른 세션은 산다" 행.

## 9. 테스트

| 그룹 | 내용 |
|---|---|
| unit | `lib/mode3_cia_state.js` v7→v8 마이그레이션; `sessionLeaf` ≠ `userLeaf`(같은 값이라도 태그로 다름); `/cia/revoke session` 분기(404·409 expired·멱등·사용자 서명·관리자) |
| circuit | 세션 리프가 트리에 있으면 거부, 없으면 통과; 사용자 리프만 있는 경우와 독립; 공개 입력 25 불변 |
| contract | 재생성 검증자로 기존 94 통과(V8 픽스처는 `s_*` 증인 포함) |
| chain | 두 세션 발급 → 하나 폐기·게시 → 그 세션 재검증/tx 는 `revoked_session`, 다른 세션은 정상, 재로그인 정상; 관리자 폐기; 만료 세션 폐기 409; 계정 폐기는 여전히 전부 죽음 |
| browser/snap | "이 세션 폐기" 버튼, Snap `signRevokeSession` 동의 창 |

## 10. 범위 밖

계정 컨트랙트 세션키 블랙리스트(B), 재기준화로 리프 접기, RCL 슬롯화, 서비스가 세션을 폐기하는 경로, 논문·슬라이드 반영(후속).
