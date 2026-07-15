# Mode 2 후속 작업: 트랜잭션 추적 (B2)

## 상태

사용자 승인 완료(2026-07-16), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

B1(`docs/superpowers/specs/2026-07-15-ppid-transaction-submission-design.md`)에서 wallet이
`PPID`를 논리적 주체로 하는 온체인 트랜잭션을 `pi_pk_i` 증명 + `sk_i` 서명으로 제출할 수
있게 됐다. B2는 그 뒤를 잇는 작업이다: 분쟁이 발생한 온체인 트랜잭션이 주어졌을 때, 인가된
주체가 그 트랜잭션을 보낸 실제 `uid`를 복원할 수 있어야 한다(PairCT 논문 Section
"CONDITIONAL PRIVACY WITH AUTHORIZED OPENING", Algorithm 2 "SESSION-SPECIFIC AUTHORIZED
OPENING" 참고, `documents/PairCT_research_article_20260706_092133_with_figures_final29_lo.docx`
최신본).

논문의 Algorithm 2는 추적을 "온체인 트랜잭션 경로"가 아니라 "RP-side 인증 트랜스크립트"에
묶는다: RP가 보관한 로그인 세션 기록(`auth_digest_i` 등)을 IdP에 제출하면 IdP가 발급
기록에서 `uid`를 복원한다. 이 프로젝트에서는 논문이 말하는 `auth_digest_i` 같은 새
아티팩트를 따로 만들지 않고, B1이 이미 만든 `pi_pk_i` 증명의 검증 가능성을 그대로
활용한다: 온체인 트랜잭션의 `pk_i`/`max_height`는 이미 calldata에 공개돼 있고, `pi_pk_i`
증명이 "이 `pk_i`가 IdP가 실제로 서명한 특정 auth token의 `r_token`에 진짜로 들어있었다"는
걸 영지식으로 증명하므로, `pk_i`는 위조 불가능한 추적 태그 역할을 한다(논문이 우려하는
"transaction-level trace tag"의 위조 가능성 문제가 `pi_pk_i`의 ZK 검증으로 이미 해소됨).

## 범위

**포함:**
- `custom_idp.js`: 발급 시점에 `r_token → uid` 매핑을 메모리에 기록, 조회 엔드포인트 추가
- `server.js`: 로그인 성공 시점에 `{auid_i, r_token, rp_nonce}` 세션 기록을 메모리에 저장,
  분쟁 트랜잭션의 `(pk_i, max_height)`로부터 해당 세션을 찾아 IdP에 조회하는 엔드포인트 추가

**명시적으로 범위 밖 (이번 반복):**
- 인가(authority) 승인 절차 — 논문도 "법적/조직적 기준은 배포 정책"이라고 명시(deployment
  policy), 이번 B2에서는 기술적 조회 메커니즘만 먼저 만들고 바로 조회 가능하게 함
- 영속 저장(파일/DB) — 메모리 전용, 서버 재시작 시 기록 소실은 의도된 데모 한계
- 조회를 트리거하는 UI — API 호출(curl 등)만 지원, B1의 `/submitTransaction`과 동일한 수준
- 논문의 `auth_digest_i`, `sid_i`, `ctx_i`, `C_u`(uid당 활성 커밋먼트) 도입 — 기존
  `r_token`/`rp_nonce`/`pk_i`/`max_height`만으로 충분하다고 판단
- B1의 회로/컨트랙트(`circuits/pi_pk_i.circom`, `contracts/PPIDWallet.sol`,
  `contracts/PPIDWalletFactory.sol`) 수정 — B2는 이 값들을 읽기만 함

## 핵심 설계 결정과 기각된 대안들

**왜 논문의 `auth_digest_i` 같은 새 조인 아티팩트를 안 만드는가?**
`pk_i`, `max_height`가 이미 온체인 calldata에 공개돼 있고, `r_token = Poseidon(pk_i,
max_height, rp_nonce)`는 IdP가 이미 서명하는 필드 중 하나다. RP가 로그인 시점에 생성한
`rp_nonce`를 보관해두면, 분쟁 트랜잭션의 공개된 `(pk_i, max_height)`와 조합해서 `r_token`을
그대로 재계산할 수 있다. 새 아티팩트를 추가하면 회로(`pi_pk_i.circom`, 이미 컴파일되어
merge된 B1의 일부)를 다시 손봐야 하므로, 기존 값 재사용이 훨씬 저렴하다.

**왜 "transaction-level trace tag" 방식이면서도 논문이 우려한 위조 가능성 문제가 없는가?**
논문은 "transaction-level trace tag"를 baseline으로 놓고 이걸 피하려 했는데, 그 이유는
일반적으로 트랜잭션에 붙는 추적 태그가 위조/재사용 가능하기 때문이다. 이 구현에서는 태그
역할을 하는 `pk_i`가 `pi_pk_i`의 Groth16 증명으로 "IdP가 실제로 서명한 유효한 auth token에
진짜로 묶여있음"이 온체인에서 강제 검증된 뒤에만 트랜잭션이 성립하므로(B1의
`PPIDWallet.execute()`), 위조된 `pk_i`로는애초에 트랜잭션 자체가 실행되지 않는다. 따라서
`pk_i`를 조인 키로 쓰는 게 논문이 우려한 문제를 재도입하지 않는다.

**왜 인가(authority) 절차를 생략하는가?**
논문 자체가 "법적/조직적 기준으로 누가 opening을 승인할 수 있는지는 배포 정책이지 PairCT의
암호학적 서브프로토콜이 아니다"라고 명시한다. 이 프로젝트는 데모/프로토타입 단계이므로,
먼저 "RP가 트랜스크립트를 제공하면 IdP가 uid를 복원한다"는 기술적 메커니즘 자체가 동작하는
것부터 검증하고, 인가 게이트는 후속 작업으로 미룬다.

**왜 메모리 전용 저장인가?**
데모 단순성을 위해 사용자가 명시적으로 선택함. 파일 기반 영속화(`wallet_agent.js`의
`wallet_state.json` 패턴)로 확장하는 건 후속 작업으로 남긴다.

## 아키텍처

```
[1] 로그인 시점 (기존 Step 9~11, server.js의 sso_success 핸들러 안)
    RP(server.js): idpToken.r_token 검증 성공 직후, req.session.rpNonce를 지우기 "직전"에
      { auid_i, r_token, rp_nonce, timestamp } 를 메모리 내 세션 로그(sessionLog)에 append

[2] 발급 시점 (기존 Step 10~11, custom_idp.js의 verifyPiIAndIssueToken 안)
    IdP(custom_idp.js): auth token 서명 직후 { r_token → uid } 를 메모리 내
      발급 로그(issuanceLog)에 저장

[3] 추적 요청 (신규, 로그인과 무관한 별도 시점)
    호출자 → server.js: POST /api/mode2/trace_transaction { pk_i, max_height }
      RP: sessionLog를 순회하며 각 rp_nonce로 Poseidon(pk_i, max_height, rp_nonce)를
          재계산 → 저장된 r_token과 일치하는 세션을 찾음
      RP → IdP: POST /idp/lookup_uid_by_r_token { r_token }
      IdP: issuanceLog에서 r_token → uid 조회, 반환
      RP → 호출자: { uid } 반환 (매칭 실패 시 404)
```

## 컴포넌트

### `custom_idp.js` (수정)
- 전역 `issuanceLog = new Map()` 추가 (메모리 전용, 프로세스 재시작 시 소실)
- `verifyPiIAndIssueToken()` 함수(263번 줄)의 `return idpToken;`(352번 줄) 직전에
  `issuanceLog.set(rToken.toString(), user.uid);` 추가 — 함수 스코프에 이미 `user.uid`
  (264번 줄)와 `rToken`(309번 줄)이 있어 최소 변경으로 가능
- 신규 엔드포인트 `POST /idp/lookup_uid_by_r_token`: 요청 본문 `{ r_token }` 필수 검증,
  `issuanceLog`에서 조회, 찾으면 `{ uid }` 200 반환, 없으면 404 + 에러 메시지

### `server.js` (수정)
- 전역 `sessionLog = []` 추가 (메모리 전용)
- `/api/mode2/sso_success` 핸들러(507번 줄)의 624번 줄(`delete req.session.rpNonce;`) 바로
  앞에 `sessionLog.push({ auid_i: idpToken.auid_i, r_token: idpToken.r_token, rp_nonce:
  sessionRpNonce, timestamp: Date.now() });` 추가
- 신규 엔드포인트 `POST /api/mode2/trace_transaction`: 요청 본문 `{ pk_i, max_height }` 필수
  검증, 둘 다 프로젝트 전역 컨벤션과 동일하게 10진수 문자열로 받는다(온체인 calldata에서
  읽은 `uint256` 값을 `.toString()`한 것 — B1의 `/submitTransaction` 응답이 이미 같은
  형식으로 `pk_i`/`max_height`를 반환하므로 별도 변환 없이 그대로 전달 가능). `sessionLog`를
  순회하며 각 레코드의 `rp_nonce`로 `Poseidon(valueToField(pk_i),
  valueToField(max_height), valueToField(record.rp_nonce))`를 재계산해 `record.r_token`과
  일치하는지 비교(server.js는 이미 `poseidon`/`valueToField`를 sso_success 검증에 쓰고
  있으므로 재사용). 일치하는 레코드를 찾으면 그 `r_token`으로 `custom_idp.js`의
  `/idp/lookup_uid_by_r_token`을 호출해서 `{ uid }`를 그대로 응답. 매칭 실패 시 404 + "No
  matching session found for this pk_i/max_height".

## 데이터 흐름

아키텍처 섹션의 [1]~[3] 단계에 이미 전부 명시돼 있다.

## 에러 처리

- `trace_transaction`: `sessionLog`에 일치하는 레코드가 없으면 404 — 분쟁 트랜잭션이 이
  RP에서 로그인한 적 없는 PPID일 수 있음을 의미
- `lookup_uid_by_r_token`: `issuanceLog`에 해당 `r_token`이 없으면 404 — 서버 재시작으로
  메모리가 소실됐거나(의도된 데모 한계), RP가 잘못된 `r_token`을 보낸 경우
- `trace_transaction`이 IdP 호출에 실패하면(네트워크 에러 등) 502 + 에러 메시지 그대로 전달

## 테스트 계획

- 로그인(Step 1~15) 1회 실행 후, 그 세션에서 실제로 쓰인 `pk_i`/`max_height`로
  `/api/mode2/trace_transaction` 호출 → 올바른 `uid` 반환 확인
- 존재하지 않는 `pk_i`로 호출 → 404 확인
- 서버(`server.js` 또는 `custom_idp.js`) 재시작 후 이전 세션의 `pk_i`로 호출 → 메모리
  소실로 404 확인 (의도된 데모 한계임을 확인하는 것이 테스트 목적)
- 여러 세션(같은 계정으로 두 번 로그인)을 만든 뒤, 각 세션의 `pk_i`로 각각 조회 → 세션별로
  올바르게 구분되는지 확인

## 후속 작업 (이 스펙 범위 밖)

- 파일 기반 영속화(서버 재시작에도 기록 유지)
- 인가(authority) 승인 절차 — 요청 → 승인 → 실제 조회의 2단계 플로우
- `client.js` 또는 별도 관리자 UI에서 추적 요청을 트리거하는 화면
- 논문의 `auth_digest_i`/`sid_i`/`ctx_i`/`C_u`(uid당 활성 커밋먼트) 개념과의 정합성 재검토 —
  현재는 기존 값 재사용으로 충분하다고 판단했지만, 논문이 최종적으로 이 아티팩트들을
  형식적 증명(Property 7 등)의 전제로 요구한다면 재검토 필요
