# 점검자 C — 서비스(RP)·회로·공개 입력 일치

대상 HEAD: `feat/mode3-cia` (64cf579). 읽기 전용. 상태·키 파일은 열지 않았다.

## 1. 판정 요약

- **Critical 없음.** π_rp 회로(`pi_cred.circom` + `mode3_commit`/`mode3_trace_tag`/`imt_nonmembership_v2`)에 `<--` 무제약 대입이 하나도 없고, 비교 전 비트폭 정규화(252/64비트), mask 게이팅, r≠0, PPID 인자 순서, 리프 유도가 모두 제약으로 걸려 있다. 공개 입력 23개의 **순서·의미는 회로 .sym / `lib/mode3_wallet.js` / `lib/mode3_rp.js` / `Mode3Wallet.sol` 네 곳이 정확히 일치**한다(§2 대응표, 회로 산출물로 실증).
- RP 검증기는 23개 공개 입력 중 **의미 있는 값을 사실상 전부** 기대값과 대조한다(arid·pk_CIA·pk_trace·chainid·revRoot·max_height 상하한·allowAgent·mask 범위·태그 형식). 빠진 것은 **선택 공개 lo/hi 9워드의 mask 필터링**과 **root 게시 나이(lastPublishedBlock)** 둘이다 — 둘 다 Important.
- π_u 는 **회로가 아니라 Σ-프로토콜**이다(`lib/mode3_issuance.js`, Fiat–Shamir Schnorr 표현 PoK). 회로 점검은 pi_cred 에 집중했다. 의뢰서의 `imt_nonmembership_v3.circom` 은 Mode 2 샤딩용이고 **Mode 3 은 V2 를 쓴다**(pi_cred.circom:5,143) — 판정 논리는 v2/v3 가 동일하고 v3 의 shardIndex 만 다르므로 문제 아님.

---

## 2. 공개 입력 23개 대응표 (**확인** — `build/mode3/pi_cred.sym` 의 main 신호 1~23 과 `pi_cred_vkey.json`(nPublic=23, IC=24) 으로 실증)

| # | 회로 신호 (`pi_cred.circom` main public) | 지갑 조립 (`lib/mode3_wallet.js:178-192`) | RP 파싱 (`lib/mode3_rp.js:52-53`) | 컨트랙트 (`contracts/Mode3Wallet.sol`) | RP 가 대조하는 기대값 |
|---|---|---|---|---|---|
| 0 | `PPID` | `PPID` | `PPID` | `pub[0] != ppid` → WrongWallet | — (세션 식별자로 기록만) |
| 1 | `arid` | `arid` | `aridIn` | `pub[1] != arid` | `reg.arid` ✓ `wrong_arid` |
| 2 | `pk_i` | `pk_i` | `pk_i` | `pub[2]` ↔ ecrecover | σ 복원 주소 ✓ `bad_signature` |
| 3 | `max_height` | `credential.max_height` | `max_height` | `pub[3]` Expired/TooFarExpiry | `head ≤ mh ≤ head+L` ✓ |
| 4 | `chainid` | `credential.chainid` | `chainIn` | `pub[4] != block.chainid` | `chainId` ✓ `wrong_chain` |
| 5 | `allowAgent` | `credential.allowAgent` | `allowAgent` | `pub[5] > 1` | `≤ 1` ✓ (정책 대조는 없음, 설계대로) |
| 6 | `revRoot` | `w.root` (증인 root 고정) | `revRoot` | `pub[6] != log.root()` | 온체인 최신 root ✓ `stale_root` |
| 7,8 | `pk_CIA_x/y` | `pk_CIA.x/y` | `ciaX/ciaY` | `pub[7],pub[8]` immutable | 고정 pk_CIA ✓ `untrusted_cia` |
| 9,10 | `pk_trace_x/y` | `pk_trace.x/y` | `traceX/traceY` | `pub[9],pub[10]` immutable | `reg.pk_trace` ✓ `wrong_trace_key` |
| 11,12 | `tag_c1_x/y` | `tag.c1.x/y` | `c1x/c1y` | `pub[11]==0 && pub[12]==1` → BadTag | 항등원 아님 ✓ `bad_tag` |
| 13 | `tag_c2` | `tag.c2` | `c2` | `pub[13]` (이벤트) | — (개봉 재료로 기록) |
| 14 | `disc_mask` | `disc.mask` | `discMask` | `pub[14] >= 16` → BadDisclosure, 꼬리·이벤트 | `< 16` ✓ `bad_disclosure` |
| 15–18 | `disc_lo[0..3]` | `disc.lo[]` | `rest.slice(0,4)` | `pub[15..18]` 꼬리 288B | **대조 없음 (발견 C-2)** |
| 19–22 | `disc_hi[0..3]` | `disc.hi[]` | `rest.slice(4,8)` | `pub[19..22]` 꼬리 288B | **대조 없음 (발견 C-2)** |

보조 확인: `cia.js:613` 개봉 경로도 같은 인덱스로 구조분해(`[PPID, aridIn, , max_height, chainIn, allowAgent, , ciaX, ciaY, traceX, traceY, c1x, c1y, c2]`)하고 `publicSignals.length !== 23` 을 강제한다. 네 곳 + CIA = **다섯 곳이 일치**.

---

## 3. 발견 목록

### Critical
없음.

### Important

**C-1. RP 로그인 검증에 폐기 root 의 "게시 나이" 검사가 없다 — 온체인 경로와 방어 수준이 비대칭 (확인)**
`lib/mode3_rp.js:55-57` / `mode3_rp.js` 전체. 검증기는 `revRoot === v.root`(온체인 최신 root)만 보고, `RevocationLog.lastPublishedBlock()` 을 **한 번도 읽지 않는다**(`grep lastPublishedBlock` 결과: 컨트랙트와 스펙에만 존재). 같은 규칙을 공유한다고 선언한 `Mode3Wallet._checkStatement`(Mode3Wallet.sol:131-132)는 `block.number - lastPublishedBlock > maxRootAge` 를 `RootTooOld` 로 막는다.
- 실패 시나리오: CIA 가 (장애든 강압이든) 폐기 게시와 하트비트를 멈춘다. 온체인 `execute` 는 `MODE3_MAX_ROOT_AGE`(기본 100블록) 뒤 전부 멈추지만, **오프체인 로그인은 무한히 계속 통과**한다. 그 사이에 폐기된 사용자는 `/api/mode3/login` 과 `/api/mode3/revalidate` 를 계속 성공시킨다 — CIA 의 로컬 트리에는 리프가 있어도 체인 root 가 안 바뀌므로 `stale_root` 가 나지 않는다. 실효 상한은 credential 의 `max_height`(≤ head+L=400블록) 뿐이고, CIA 가 발급은 계속한다면 그마저도 갱신된다.
- 문서와의 어긋남: `2026-09-09 §8.5` 는 "RP 는 블록 헤드로 체인 생존을 알 수 있어 하트비트가 필요 없다 / withholding 최대 노출 = 헤드 신선도 10분"이라고 적는다. 그러나 `headMaxAgeMs`(10분)는 **RPC 가 실패했을 때 캐시 허용치**일 뿐이고, 헤드 높이는 *체인*의 생존만 말하지 *CIA 게시*의 생존은 말하지 않는다. 2026-09-18 에 `lastPublishedBlock` + 하트비트가 실제로 도입되면서 §8.5 의 전제가 깨졌는데 오프체인 검증기만 그대로 남았다.
- 고치는 방향: `chainView()` 에서 `log.lastPublishedBlock({blockTag: head})` 도 함께 읽어 `head - lastPublished > MODE3_MAX_ROOT_AGE` 면 `root_too_old` 로 거절(온체인과 같은 상수·같은 이름).

**C-2. 선택 공개 lo/hi 를 mask 로 거르지 않고 세션·로그인 로그·UI 에 그대로 싣는다 (확인)**
`lib/mode3_rp.js:53,79` → `mode3_rp.js:207,240-244,342` → `mode3/rp.html:117,215-216`. 회로는 mask 비트가 0 인 슬롯의 `disc_lo[k]/disc_hi[k]` 에 **64비트 범위 말고는 아무 제약도 걸지 않는다**(`pi_cred.circom:184`, `maskBits.out[k] * (1 - discOk[k]) === 0`; `tests/test_pi_cred_witness.mjs:215` 가 "공개하지 않는 슬롯의 lo·hi 는 무시된다"를 양성으로 고정). 설계 §4.2 는 "공개하지 않는 슬롯은 **지갑이** lo = hi = 0 으로 채운다"고 적어 정직한 지갑을 전제하는데, 검증자가 그것을 강제하지 않는다.
- 실패 시나리오: 수정된 지갑이 `disc_mask = 0b0001`(슬롯 0 만 실제 공개)로 두고 `disc_lo=[0, 410, 0, 0]`, `disc_hi=[2007, 410, 0, 0]` 을 넣어 로그인한다. 증명은 정상 통과하고(슬롯 1 은 아무 제약 없음), RP 는 `session.disclosure` 와 `mode3_rp_logins.jsonl`, `/api/mode3/sessions`, `/api/mode3/logins`, RP 페이지에 `disclose(mask=1): lo=0,410,0,0 hi=2007,410,0,0` 을 그대로 찍는다. 화면·로그만 보는 운영자/후속 연동은 "국가 = 410 이 AA 보증으로 공개됐다"고 읽지만 **회로는 슬롯 1 을 전혀 검증하지 않았다.** (온체인 `AttrGate` 는 `mask & 0x3 == 0x3` 을 요구해 안전하다 — 위험은 RP 측 표시·기록 경로에 한정된다.)
- 고치는 방향: `verifyLogin` 이 돌려주는 `disclosure` 에서 mask 비트가 0 인 슬롯의 lo/hi 를 0 으로 정규화하거나(또는 `lo=hi=0` 이 아니면 `bad_disclosure`), RP·UI 가 mask 비트로 슬롯을 걸러 표시한다.

### Minor

**C-3. `/api/mode3/open` 의 txHash 경로에 지역 arid·팩토리 검사가 없다 (확인)**
`mode3_rp.js:294-331`. `transcriptFromTx` 는 임의의 트랜잭션에서 `execute` calldata 를 디코드해 `pub[11..12]` 를 그대로 `partialDecrypt(x_svc, c1)` 에 넣고 CIA 로 보낸다. `d.pub[1] === reg.arid` 나 "tx.to 가 내 팩토리의 지갑인가"를 보지 않는다. 공격자가 `execute(...)` 시그니처를 받아 `Mode3Auth` 를 흉내 내는 자기 컨트랙트를 배포하면 임의의 `c1` 에 대해 RP 가 `D_svc = x_svc·c1` 을 계산·서명하게 만들 수 있다. **실제 유출은 없다** — `D_svc` 는 응답으로 돌아오지 않고 CIA 로만 가며, CIA 가 `wrong_arid`·`wrong_trace_key`·`bad_proof` 로 막는다(cia.js:615-627). 즉 지금은 CIA 검사 하나에만 기대는 구조다.
- 고치는 방향: `transcriptFromTx` 에서 `d.pub[1] !== reg.arid` 면 `wrong_arid` 로 조기 거절(가능하면 `tx.to` 가 `reg.factoryAddress` 의 지갑인지도).

**C-4. 메모리 맵·배열에 상한·만료 청소가 없다 (확인)**
`mode3_rp.js:186-187,203`. `challenges` 는 `issueChallenge` 때만 sweep 하고(`sweepChallenges`), `sessions` 는 `/api/mode3/request` 가 만료를 만났을 때만 지워지며(`mode3_rp.js:276`), `logins` 배열은 영원히 자란다. 인증 없는 `/api/mode3/challenge` 를 반복 호출하면 TTL(120초) 창 안에서 무제한으로 엔트리가 쌓인다. 로그인하고 `/request` 를 안 부르는 세션은 영구히 남는다. 데모 규모에서는 문제되지 않지만 장시간 기동 시 메모리만 는다.
- 고치는 방향: 주기적 sweep(세션은 `max_height` 지난 것 제거), `logins` 길이 상한.

**C-5. `/api/mode3/revalidate` 가 `max_height`·`allowAgent` 를 갱신하지 않는다 (확인)**
`mode3_rp.js:248-263`. 재검증은 `s.root` 와 `s.disclosure` 만 갱신한다. 새 π 의 `max_height`/`allowAgent` 가 달라져도 세션에는 로그인 때 값이 남아, `/api/mode3/request` 의 만료 판정(`view.head > BigInt(s.max_height)`)과 `/api/mode3/sessions` 표시가 최신 성명과 어긋날 수 있다. 세션 연장은 되지 않으므로(옛 값이 더 짧으면 먼저 죽는다) 안전 방향이지만, 표시·판정의 정합성은 깨진다.
- 고치는 방향: 재검증 성공 시 `s.max_height`·`s.allowAgent` 도 갱신하거나, 값이 달라지면 `session_mismatch`.

**C-6. 세션키 서명 메시지에 도메인 분리 접두사가 없다 (확인, 현재는 충돌 없음)**
`lib/mode3_wallet.js:207-213` / `lib/mode3_rp.js:74,87`. 로그인 챌린지는 `"${r_s}"`, 세션 요청은 `"${r_s}:${body}"` — 지금은 전자가 순수 숫자라 충돌이 없다. 다만 `"mode3-login:"` 같은 접두사가 없어, 세션키가 다른 용도(온체인 payload 는 EIP-191 이 아니라 keccak digest 라 무관)로 확장될 때 교차 프로토콜 재사용 위험이 생긴다.

**C-7. 문서/주석 잔재 (확인)**
- `contracts/Mode3Wallet.sol:8` — "검증자가 pi_cred(공개 입력 14개)"(실제 23개). 본문 NatSpec(67-70행)은 23개로 맞다.
- `circuits/pi_cred.circom:25` — "attrs[4] 는 C_u 에만 실린다 — CIA 는 값을 모르고 … **이 회로는 술어를 검증하지 않는다**". V6(§1, §4.2)에서 둘 다 뒤집혔다(AA 가 값을 알고, 회로가 술어를 검증한다). 같은 파일 17·172행의 V6 주석과 모순된다.
- `docs/superpowers/specs/2026-09-09 §8.5` — C-1 참조.

### 한계로만 (버그 아님, 문서에 이미 있음)
- 로그인 시 서비스가 특정 공개를 **요구**하는 정책이 없다(기록만). 선택 공개 설계 §6.2·§11(a) 가 "열린 것"으로 명시.
- `/api/mode3/open*`, `/api/mode3/sessions`, `/api/mode3/logins` 무인증(설계 §7 M4).
- `pk_CIA` TOFU, 릴레이어 = hardhat 언락 계정, 로컬 HTTP.

---

## 4. 강점 (다음 점검자가 다시 볼 필요 없는 것)

1. **회로 건전성**: `pi_cred.circom`·`mode3_commit.circom`·`mode3_trace_tag.circom`·`imt_nonmembership_v2.circom` 에 `<--` 가 **0건**. 비교기 입력은 전부 사전 분해된다 — IMT 는 `Num2Bits_strict` + 하위 252비트 마스킹 후 `LessThan(252)`, 술어는 `Num2Bits(64)`×(attrs, lo, hi) 후 `LessEqThan(64)`(`in[1]=hi+1 ≤ 2^64` 라 `LessThan(64)` 의 `Num2Bits(65)` 범위 안 — 오버플로 없음). `allowAgent*(allowAgent-1)===0`, `max_height` Num2Bits(64), `pk_i` Num2Bits(160), 스칼라 Num2Bits(250)(<2^250 < 부분군 위수 2^251.4 라 Pedersen binding 유지) 모두 제약이다.
2. **mask 게이팅·r≠0·PPID·리프 유도**: `maskBits.out[k]*(1-discOk[k])===0` 이 정확히 "공개하는 슬롯만 강제"이고 `disc_mask` 는 `Num2Bits(4)` 로 <16 이 강제된다. `rNZ.out === 0` 로 r=0 을 회로가 막고 RP·컨트랙트·CIA 가 각각 c1=(0,1) 을 한 번 더 막는다(4중). PPID = `Poseidon(uid, s_u, chainid, arid)` 가 정확히 그 순서(JS `ppid()` 와 일치)이고, 폐기 리프는 `Poseidon(4, Cf_u)` 를 **비공개 입력에서 회로가 직접 계산**하므로 증명자가 다른 리프를 들이밀 수 없다.
3. **빈 트리 anchor**: `lib/imt_v2.js:56-61` 이 빈 슬롯을 리터럴 `0n` 으로 두어 anchor `Poseidon(0,0,0)` 과 모양이 겹치지 않는다 — "빈 슬롯을 low 리프로 제시해 임의 값의 거짓 비멤버십"이 원천 차단. JS(`leafValue`, `getNonMembershipWitness`)와 회로가 **같은 252비트 마스킹**을 쓴다(lib/imt_v2.js:327,353 ↔ imt_nonmembership_v2.circom:74-81).
4. **RP 검증 순서와 fail-closed**: 싼 검사(키·arid·chainid·범위·태그) → Groth16 → σ 순서라 DoS 내성이 있고, 체인을 못 읽으면 10분 캐시 뒤 `chain_unavailable` 로 **거절**한다. `revRoot` 는 증인 root 로 고정해(`mode3_wallet.js:175`) 트리 공유 시 경합을 막았다. `publicSignals` 를 정규 10진으로 돌려줘 개봉 때 CIA 의 문자열 비교와 어긋나지 않게 한 것(앞자리 0 테스트 포함)도 견고하다. snarkjs 0.7.5 의 `publicInputsAreValid` 가 ≥p 인 공개 입력을 거르므로 "필드 밖 값으로 RP 검사와 증명 해석을 갈라놓기"는 불가능하다(확인).
5. **챌린지**: `consumeChallenge` 가 **검증 전에** 삭제 → 1회성, TTL 만료도 거절. σ 가 서버가 준 r_s 위임을 RP 가 자기 값으로 검증(클라이언트가 보낸 r_s 를 신뢰하지 않음). 재사용·다른 r_s·다른 키 모두 테스트가 고정(`tests/test_mode3_rp.mjs:92-107`, `test_mode3_demo_stack.mjs:219,419`).
6. **비밀 취급**: `x_svc`·`sk_service` 는 어떤 응답·로그·HTML 에도 나오지 않는다(전체 grep 확인). 등록 파일은 `writeJsonAtomic(..., 0o600)`(`lib/mode3_state.js:13-16`, openSync 에 mode 지정)로 쓰고, 로그인 로그는 기동 시 기존 파일까지 `chmod 0600`. 둘 다 `.gitignore` 에 있다. 로그인 로그 한 줄의 내용은 개봉 설계 §5 의 규약(전체 r_s + 트랜스크립트 + proof)과 일치하며 조회 API 로는 r_s 8자리 축약만 나간다.
7. **테스트**: `tests/test_pi_cred_witness.mjs`(27건: 서명이 덮는 필드 전부의 음성, r=0, 태그 4종, 폐기 전후, V6 mask 6종), `tests/test_mode3_rp.mjs`(23건: 7단계 전부의 양·음성 + 캐시 fail-closed + 앞자리 0 + chainid 별 PPID), `test_mode3_demo_stack.mjs`(HTTP 경로·개봉·AttrGate·선택 공개 시나리오)가 이 영역을 조밀하게 덮는다. 모두 `scripts/run_tests.sh` 의 circuit/chain 그룹에 등록돼 있다.

---

## 5. 점검하지 못한 것과 이유

- **테스트를 실행하지 않았다** — 공통 지침이 읽기 전용·서버 기동 금지이므로 정적 대조와 회로 산출물(`pi_cred.sym`, `pi_cred_vkey.json`) 조회만 했다. 따라서 C-1/C-2 는 코드·문서 대조에 근거한 것이고 실행 재현은 하지 않았다(둘 다 "확인" 등급이나, PoC 실행은 미수행).
- **`PiCredVerifier.sol` 의 내부**(Groth16 pairing 상수가 `pi_cred_final.zkey` 와 같은 회로에서 나왔는지) — 점검자 D 범위이고, 여기서는 `uint[23]` 인터페이스 일치만 확인했다.
- **`mode3_rp_registration.json`·`mode3_rp_logins.jsonl` 의 실제 내용·권한** — 지침상 열지 않았다. 코드가 0600 으로 만들고 조인다는 것만 확인.
- **`lib/mode3_rcl_sync.js`·`tests/test_mode3_rcl_sync.mjs`** — 공통 지침의 점검 제외 대상.
- **CIA 측 개봉 승인 경로의 전체**(`/cia/openings/:id/approve` 의 `resolveTagPlaintext` 등) — 점검자 A/B 범위로 보고, RP → CIA 인터페이스 대조에 필요한 만큼만 읽었다.
- **브라우저 UI 전체**(`mode3/rp.html`) — C-2 에 관련된 표시 경로만 grep 으로 확인했고 전체 흐름은 보지 않았다.
