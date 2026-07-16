# B1/B2 확장이 만족하는 특성: 논문 정의 형식 초안

**작성일**: 2026-07-17
**범위**: `trace` 브랜치의 B1(PPID 기반 트랜잭션 제출)과 B2(트랜잭션 추적) 확장이 실제
구현·테스트로 확인한 성질을, PairCT 논문(`documents/PairCT_research_article_*.docx`
최신본)의 Definition 1/2/4, Property 7과 같은 형식으로 정리한 것.

**주의**: 이 문서의 정의들은 실제 구현(회로/컨트랙트/엔드포인트)을 컴파일·배포·라이브
테스트한 결과를 바탕으로 서술한 것이지, 논문 본문의 "Extraction-aware analysis model"
(Groth16 argument-of-knowledge 기반의 형식적 축약 증명)까지 거친 정리(theorem)는
아니다. 논문에 편입하려면 해당 절의 형식에 맞춰 별도의 축약 증명이 필요하다.

## 표기

기존 논문 표기(`uid, rid, salt, auid, arid_i, auid_i, rho_i` 등)를 그대로 쓴다. B1/B2에서
새로 도입한 표기:

- `sk_i / pk_i`: secp256k1 세션 서명키와 그 이더리움 주소. **지갑 프로세스(`wallet_agent.js`)
  당 영속**되며, 세션(로그인)마다 새로 생성되지 않는다(B1 설계 결정, 논문의 세션 단위
  아티팩트 모델과 다름 — 아래 Definition B2 참고).
- `r_token = H_Poseidon(pk_i, max_height, rp_nonce)`: IdP가 서명하는 인증 토큰 필드 중
  하나. `pi_pk_i` 회로 안에서 재계산·검증됨.
- `PPIDWallet_ppid`: `CREATE2(factory, ppid, bytecode)`로 결정되는, `ppid`별
  스마트컨트랙트 지갑 주소. 최초 사용 전까지는 지연 배포 상태(counterfactual).
- `execute()`: `PPIDWallet_ppid`가 노출하는 함수. `(payload, sig, pi_pk_i, pk_i, pk_IdP,
  max_height)`를 받아 6단계로 검증한 뒤 실행한다.

## Definition B1 (Unforgeable On-Chain Transaction-Token Binding)

**PairCT-B1이 unforgeable transaction-token binding을 만족한다**는 것은, 임의의 PPT
적대자가 유효한 IdP 서명 인증 토큰(구체적으로, 그 토큰의 `r_token` 필드에 실제로 묶인
`pk_i`에 대응하는 `sk_i`)을 모르는 상태에서, `PPIDWallet_ppid.execute()`가 받아들이는
`(payload, sig, proof)` 삼중값을 만들어낼 확률이, Groth16 argument-of-knowledge 성질과
secp256k1 서명 위조 불가능성 가정 하에서 무시할 수 있는 수준이라는 뜻이다.

**근거**: `execute()`는 다음을 동시에 요구한다(순서대로, `contracts/PPIDWallet.sol`):
1. `payload.nonce == 저장된 nonce` (재사용 방지)
2. `ecrecover(payloadHash, sig) == pk_i`
3. `(pk_IdP_x, pk_IdP_y) == 저장된 신뢰 IdP 키`
4. `pi_pk_i`가 `(pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height)`에 대해 검증됨
5. (b)와 (d)의 `pk_i`가 동일 (구조상 자동 성립)
6. `block.number <= max_height`

`pi_pk_i`(`circuits/pi_pk_i.circom`)는 회로 안에서 `r_token = H_Poseidon(pk_i,
max_height, rp_nonce)`이면서 그 `r_token`이 IdP의 EdDSA-Poseidon 서명 대상 메시지
`H_Poseidon(DOMAIN, arid_i, auid_i, r_token, max_height, chain_id)`의 구성요소임을
강제한다. 따라서 위조된 `pk_i`로는 유효한 `pi_pk_i`를 만들 수 없다 — 실제로 회로를
컴파일하고, 유효한 witness는 통과·조작된 witness(`auid_i` 변조)는 거부되는 것을
확인했고, 컨트랙트도 실제 Hardhat 노드에 배포해서 정상 실행/서명 조작 거부/nonce
재사용 거부를 라이브로 검증했다(2026-07-15~16).

**따름정리 B1.1 (Unforgeable Trace Tag)**: 위 정의가 성립하면, 온체인에 공개된 `pk_i`는
"위조 불가능한 추적 태그"로 쓸 수 있다 — 일반적인 "transaction-level trace tag" 방식이
가진 문제(누구나 임의의 태그를 자유롭게 붙일 수 있어 신뢰할 수 없음)가 여기서는 zk 증명
검증 덕분에 발생하지 않는다.

## Definition B2 (Session-Linked Conditional Opening, via Reused Artifacts)

**PairCT-B2가 조건부 개방성을 만족한다**는 것은, 분쟁이 된 온체인 트랜잭션에서 공개적으로
관찰 가능한 `(pk_i, max_height)`와 RP가 보관한 세션 기록(`rp_nonce`)이 주어졌을 때,
`r_token = H_Poseidon(pk_i, max_height, rp_nonce)`을 재계산해 IdP의 발급 기록
`(r_token → uid)`을 조회함으로써 인가된 주체가 `uid`를 복원할 수 있다는 뜻이다.

**근거**: `custom_idp.js`는 인증 토큰 발급 시 `(r_token → uid)`를 기록하고,
`server.js`는 로그인 성공 시 `(auid_i, r_token, rp_nonce)`를 기록한다. `trace_transaction`
엔드포인트는 분쟁 트랜잭션의 `(pk_i, max_height)`로 저장된 각 세션의 `rp_nonce`를 대입해
재계산한 값이 저장된 `r_token`과 일치하는 세션을 찾고, 그 `r_token`으로 IdP에 조회를
위임한다. 실제 로그인 → 추적 왕복을 라이브로 검증했고(정상 조회, 존재하지 않는 값 404,
다중 세션 독립 구분, 서버 재시작 후 소실 확인), 매칭 로직이 `pk_i` 단독이 아니라
`(pk_i, max_height, rp_nonce)` 전체 튜플에 대해 정확하게 동작함을 확인했다.

### 논문 Definition 4 / Property 7과의 차이 (중요)

논문의 원래 설계는 `auth_digest_i`가 **세션마다** 새로 생성되는 아티팩트라서, 하나의
트랜스크립트를 여는 것이 딱 그 세션 하나만 연다. 반면 이 구현은 (a) `sk_i`/`pk_i`를
지갑 프로세스당 영속시키는 B1의 설계 위에 얹혀 있어서, **같은 `pk_i`가 여러 세션·여러
트랜잭션에 걸쳐 재사용**된다. 그 결과:

- `pk_i` 자체가 이미 온체인에서 공개적으로 관찰 가능하므로, **개방(opening) 이전에도**
  외부 관찰자가 같은 `pk_i`를 쓰는 모든 트랜잭션을 서로 링크할 수 있다(이건 B1의
  성질이지 B2가 새로 만든 문제는 아니다).
- B2의 개방 절차 자체는 여전히 "이 `r_token`(=이 특정 세션)에 대응하는 `uid`"만
  복원하지만, 그 `uid`를 알고 나면 이미 관찰 가능했던 "같은 `pk_i`를 쓰는 트랜잭션
  전체"가 한꺼번에 그 `uid`로 귀속된다.

즉 **개방 절차 자체(Definition B2)는 세션 단위로 정확하지만, 그 위에 놓인 `pk_i`
영속성(B1)이 개방의 실효적 파급 범위를 논문의 원래 세션 단위보다 넓힌다.** 이건 B2
코드의 결함이 아니라 B1+B2를 같이 쓸 때 드러나는 emergent 성질이며,
`docs/superpowers/specs/2026-07-16-b2-transaction-tracing-design.md`의 "후속 작업"
섹션에도 기록해두었다.

## 이번 반복에서 명시적으로 안 만족하는 것 (한계)

- **인가(authority) 게이트 없음**: 지금 `trace_transaction`/`lookup_uid_by_r_token`은
  값만 맞으면 누구나 호출 가능하다 — 논문의 "authorized opening"에서 "authorized"
  부분이 이번 반복엔 구현되지 않았다(의도적 범위 제한이며, 자동 보안 스캐너도 이
  지점을 지적한 바 있다).
- **영속성 없음**: RP/IdP 로그가 메모리 전용이라 프로세스 재시작 시 개방 가능성 자체가
  사라진다(가용성 특성이지, 안전성 특성 위반은 아니다).
- **`chain_id` 미검증**: `pi_pk_i`가 `chain_id`를 private input으로만 다루고 온체인에서
  `block.chainid`와 대조하지 않는다 — 같은 factory가 여러 체인에 배포되면 재생 공격
  가능성이 있다(B1 최종 리뷰에서 확인, 단일 체인 데모에선 해당 없음).

## 참고: ZKP 크기/생성 시간 실측치 (2026-07-16/17 측정)

| 회로 | public input 수 | 온체인 계산(증명 256B + public signals) | 생성 시간(워밍업 후, 10회) |
|---|---|---|---|
| `pi_arid_i` | 5 (uid, arid_i, auid_i, max_height, token_nonce) | 416B | 63.1–68.6 ms |
| `pi_ppid` | 2 (rid, ppid) | 320B | 48.2–51.5 ms |
| `pi_pk_i` | 5 (pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height) | 416B | 215.2–236.0 ms |

Groth16 증명 자체는 회로 크기와 무관하게 항상 256바이트(고정 8개 필드 원소)이며, 회로마다
다른 건 public input 개수뿐이다. 최초 호출은 BN128 커브 WASM 초기화 + V8 JIT 웜업
비용으로 인해 훨씬 느리지만(예: `pi_pk_i` 첫 호출 ~700ms), 이는 파일 I/O가 원인이
아니며(별도로 확인함), `wallet_agent.js` 기동 시점에 `pi_pk_i`를 4회 미리 호출하는
것으로 프로세스 전체(다른 회로 포함)가 웜업되어 첫 실사용자 요청부터 안정적인 속도로
동작함을 확인했다.
