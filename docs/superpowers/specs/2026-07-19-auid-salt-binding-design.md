# Mode 2 후속 작업: auid(=H(uid,salt)) 기반 Wallet-IdP salt 바인딩 체크

## 상태

사용자 승인 완료(2026-07-19), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

2026-07-17 미팅 정리 항목 중 "PPID uniqueness를 session 내 검증 + session 간 검증으로 정리"와 "Wallet-IdP 직접 통신방식의 보안 안전성 검증" 두 가지에 대응하는 작업이다.

지금까지는 지갑(`wallet_agent.js`)이 매 로그인마다 `salt`(계정당 영속 비밀값)를 그대로 재사용하는지 IdP가 검증할 방법이 없었다. 지갑이 (버그로든, 악의적으로든) 로그인마다 다른 `salt`를 쓰면, `ppid`(= `H(uid, rid, salt)`)가 매번 달라져서 사실상 다른 지갑인데도 같은 `uid`로 로그인에 성공해버린다 — RP 입장에서는 같은 계정의 여러 "다른 지갑들"이 존재하는 것처럼 보이는 상태가 된다. 이걸 막으려면 IdP가 "이 uid는 지난번과 같은 salt를 쓰고 있다"는 걸 세션 간(cross-session)으로 확인할 방법이 필요하다.

## 용어 정리 (이번에 확정, 논문과 다름 — 별도 후속 작업으로 논문도 개정 예정)

- **`ppid`(코드) = `PPID`(논문) = `H(uid, rid, salt)`** — 기존과 동일, 이번에 이름/공식 변경 없음. 논문에서 지금까지 "auid"라고 부르던 값이었으나, 이번 결정으로 논문도 `PPID`로 용어를 통일하기로 함(별도 후속 논문 개정 작업).
- **`auid`(신규, 코드+논문 공통) = `H(uid, salt)`** — 이번에 새로 도입하는 값. `rid` 없이 계정당(모든 RP 공통) 고정. RP FE에는 전달되지 않고 IdP에게만 전달되며, ZK 증명 안에서 검증된다. salt 재사용 여부를 IdP가 세션 간에 확인하는 용도.
- `auid_i`, `arid_i` — 기존과 동일, 이번 변경과 무관(`auid_i = ppid * rp_nonce`).

새 `auid`와 논문의 예전 "auid" 정의가 이름이 겹치는 것에 유의 — 코드/설계 문서 전반에서 이제 `auid`는 항상 `H(uid,salt)`(새 값)를 가리킨다.

## 범위

**포함:**
- `circuits/pi_arid_i.circom`: `uid`, `salt`는 이미 이 회로의 private witness다. 새 `signal input auid;`를 public 입력으로 추가하고, `pi_ppid.circom`과 동일한 패턴으로 `auid === bindHasher.out;`(단순 `<==` 대입이 아니라 `===` 등식 제약)으로 강제 검증한다 — 프로버(지갑)가 실제 `uid`/`salt`와 다른 `auid`를 몰래 제출해도 증명 자체가 실패하게 만들기 위함. public 리스트 맨 끝에 추가: `component main {public [uid, arid_i, auid_i, max_height, token_nonce, auid]}`.
- `wallet_agent.js`: Step 8 핸들러에서 `auid`도 같이 계산해서 `pi_arid_i`의 witness(`aridInputs`)에 포함.
- `custom_idp.js`:
  - `users[username]`에 `lastAuid: null` 필드 추가(최초엔 없음, in-memory, 서버 재시작 시 소실 — 기존 `usedNonces`/`issuanceLog`/`sessionLog`와 동일한 데모 한계).
  - `verifyPiIAndIssueToken()`에서 `pi_i`(=pi_arid_i) Groth16 증명 검증이 성공한 **직후**(다른 필드 대조보다 먼저, 증명이 유효하지 않은 상태에서 저장값을 오염시키지 않기 위해): 증명의 public signal에서 `auid`를 읽어서, `users[username].lastAuid`와 비교.
    - `lastAuid`가 없으면(최초 로그인): 그냥 저장하고 통과.
    - `lastAuid`가 있고 새 `auid`와 다르면: 인증 거부(로그인 실패 처리, 토큰 발급 안 함).
    - 같으면: 통과(값 재저장은 해도 그만 안 해도 그만, 같은 값이라 상태 변화 없음).
  - 길이 검증 상수 갱신: `assertDecimalSignals(zkpPublicSignals, 4, ...)` → `5`(uid 뺀 나머지가 4개에서 5개로), `assertDecimalSignals(verifySignals, 5, ...)` → `6`.
- `client.js`: 로직 변경 없음(파일 자체를 안 건드림) — `zkpSignalsWithoutUid()`가 이미 "uid만 잘라내고 나머진 그대로 전달"하는 구조라 새 시그널이 하나 늘어도 자동으로 같이 전달된다. (참고용으로 스펙에 남겨둠 — 실제 코드 변경 없음.)

**명시적으로 범위 밖:**
- `circuits/pi_ppid.circom`, `circuits/pi_pk_i.circom`, `contracts/*.sol`, `server.js` — 이 값과 무관, 변경 없음.
- 논문(`documents/*.docx`) 개정 — 별도 브레인스토밍/작업으로 진행.
- `auid_i = ppid * rp_nonce` 관계 — 그대로 유지.

## 핵심 설계 결정

**왜 새 회로가 아니라 `pi_arid_i.circom`에 넣는가?**
`uid`와 `salt`는 이미 이 회로의 private witness다(`ppid` 내부 유도에 쓰임). 새 값 하나 더 계산해서 public으로 노출시키기만 하면 되므로, 별도 회로(새 파일, 새 zkey/vkey, 새 `fullProve`/`verify` 호출)를 만드는 것보다 변경 범위가 훨씬 작다. `token_nonce`도 이미 같은 방식(같은 회로 안에서 Poseidon 계산 후 public으로 노출)으로 처리되고 있어 기존 패턴과 일관된다.

**왜 public 리스트 맨 끝에 추가하는가?**
`custom_idp.js`의 기존 인덱스 기반 검증(`verifySignals[1]`=arid_i, `[2]`=auid_i, `[3]`=max_height, `[4]`=r_token)이 안 밀리게 하기 위해서다. 맨 끝에 추가하면 기존 4개 검증 로직은 그대로 두고, `verifySignals[5]`(새 `auid`)에 대한 검증만 추가하면 된다.

**왜 증명 검증 성공 "직후"에 auid를 비교/저장하는가?**
증명이 유효하지 않다면 그 안의 `auid` 값도 신뢰할 수 없다 — 위조된 증명으로 `lastAuid` 저장값을 오염시키는 걸 막기 위해, 반드시 Groth16 검증 통과 이후에만 비교/저장한다.

**왜 "최초 로그인이면 저장"인가, 별도 enrollment 단계가 없는 이유는?**
사용자가 "커밋먼트(등록) 단계는 안 하기로 했다"고 명시적으로 결정함 — 형식적인 등록 절차 없이, 그냥 "가장 최근 성공한 로그인의 값"을 계속 갱신 대조하는 단순한 방식을 택했다. 최초 로그인은 비교 대상이 없으니 자연스럽게 통과시키고 저장한다.

## 테스트 및 검증

- `circuits/pi_arid_i.circom` 회로 레벨 테스트: 기존 `tests/test_pi_arid_i_no_rid.js`에 `auid` 입력 계산을 추가하고, public 시그널 개수가 6개로 늘었는지 확인.
- 신규 테스트: `auid` 불일치 시 `custom_idp.js`가 실제로 로그인을 거부하는지 확인(같은 `uid`, 다른 `salt`로 두 번 로그인 시도 시뮬레이션).
- 회로/zkey 재생성 필요(`pi_arid_i`만, `pot14_final.ptau` 재사용 — PPID Poseidon 전환 때와 동일 패턴).
- 라이브 검증: 서버 재시작(`custom_idp.js` pk_IdP 재생성 → `PPIDWalletFactory` 재배포 필요, 지난번과 동일 패턴) 후 브라우저 로그인 테스트.
