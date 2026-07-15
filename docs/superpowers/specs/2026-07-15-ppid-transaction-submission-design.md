# Mode 2 후속 작업: PPID 기반 트랜잭션 제출 (B1)

## 상태

사용자 승인 완료(2026-07-15), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

EdDSA-Poseidon auth token 마이그레이션이 `master`에 병합된 이후, 사용자의 PPT
(`documents/260710_meeting_MHJ.pptx`, slide 3-4, 25-27, 30)는 후속 기능을 설명합니다:
Mode 2 로그인(Step 1~15)이 끝난 뒤, wallet이 "PPID로서" 블록체인 트랜잭션을 제출할 수 있고
(slide 3, "Send and Verify Transaction"), 이게 나중에 규제 목적(AML/Travel Rule, slide 25)으로
인가된 절차를 통해 실제 `uid`로 역추적될 수 있어야 합니다(slide 4, "Trace User from
Transaction").

이건 순차적인 두 개의 하위 작업으로 나뉩니다(추적은 제출된 트랜잭션이 있어야 하니 뒤에 옴):

- **B1(이 스펙): 트랜잭션 제출.** 새 `pi_pk_i` zk 회로와 온체인 인프라를 만들어서, wallet이
  "PPID"를 논리적 주체로 하는 트랜잭션을 제출하되, **실제로 강제되는** 온체인 검증을 받도록
  합니다(그냥 데이터만 첨부하고 신뢰하는 게 아니라).
- **B2(추후, 별도 브레인스토밍 사이클): 추적.** 인가된 주체가 나중에 PPID가 표시된
  트랜잭션에서 `uid`를 어떻게 복원하는지. 여기서는 설계 안 함.

이 스펙은 B1만 다룹니다.

## 범위

**포함:**
- 새 `circuits/pi_pk_i.circom` 회로
- 새 Solidity 컨트랙트: `CREATE2` factory + PPID별 지갑 컨트랙트
- `wallet_agent.js` 변경: Step 8의 세션 키(`pk_i`/`sk_i`)를 P-256 → secp256k1로 변경,
  이 로그인-이후 흐름을 위한 payload 서명 + `pi_pk_i` 증명 생성 로직 추가

**명시적으로 범위 밖:**
- B2 추적 메커니즘(트랜잭션에서 `uid`를 어떻게 복원하는지) — 별도 스펙
- 기존 `PPID = uid * rid * salt` 공식이나 Mode 2 Step 1~15 로그인 흐름 자체를 바꾸는 것 —
  이 기능은 Step 15가 끝난 뒤에만 실행되는, 순수하게 추가되는 기능입니다
- 가스비 지불 프라이버시를 위한 릴레이어 서비스(논의했으나 의도적으로 보류 — 데모는 일단
  이미 자금이 있는 Hardhat 계정을 가스비 지갑으로 재사용)
- `pi_arid_i.circom`, `pi_ppid.circom`은 수정하지 않음

## 핵심 설계 결정과 기각된 대안들

이 섹션은 "무엇을"뿐 아니라 "왜"를 기록합니다 — 설계 과정에서 그럴듯해 보이는 여러 대안을
검토했다가 기각했는데, 나중에(미래 세션 포함) 이걸 처음부터 다시 유도할 필요가 없도록
하려는 목적입니다.

**왜 평범한 이더리움 트랜잭션에 `sender: PPID`를 쓰면 안 되는가?**
이더리움 프로토콜은 트랜잭션의 `sender`를 항상 그 트랜잭션 자체의 ECDSA 서명에서
`ecrecover`로 역산합니다 — 가장 최근 것(EIP-7702)을 포함해서, sender가 서명 키와 분리된
임의의 값이 될 수 있는 트랜잭션 타입은 컨트랙트 코드를 거치지 않고는 없습니다. 커스텀
조건(zk 증명)에 대한 실제 네트워크 강제 검증은 스마트컨트랙트 코드 안에서만 가능합니다 —
컨트랙트 없이는 진짜 온체인 강제성을 얻을 방법이 없습니다. ("증명을 calldata로 첨부만 하고
나중에 오프체인으로 검증"하는 순수 설계도 검토했다가 기각했습니다: 이건 *검증 가능성*은
유지합니다 — Groth16 증명은 설계상 누구나 공개키로 검증 가능하니까요 — 하지만 *강제성*은
없습니다: 무효하거나 재사용된 증명도 일단 온체인에 올라갈 수 있고, 재사용 방지는 오프체인
레지스트리에 의존하게 되는데 이게 새로운 신뢰된 제3자 의존성이 됩니다. 이 기능의 핵심
가치가 신뢰할 수 있는 추적성이라는 점을 감안하면, 강제성 쪽이 컨트랙트를 만드는 추가
엔지니어링 비용보다 더 중요하다고 판단했습니다.)

**왜 사용자마다 컨트랙트를 미리 배포하는 대신 공용 relay/factory 컨트랙트인가?**
모든 등록된 사용자에게 컨트랙트를 미리 배포해두는 건 불필요하게 무겁다고 판단해 기각했습니다.
선택한 설계(`CREATE2`, 최초 지출 시점에 지연 배포)는 "PPID가 진짜 자기 주소를 갖는다"는
속성을 사전 배포 비용 없이 동일하게 얻습니다.

**왜 PPID의 주소는 자기 개인키를 가질 수 없는가?**
`PPID = uid * rid * salt mod FIELD_PRIME`은 특정 개인키의 공개키 해시로 나올 수 없는,
겉보기에 임의적인 필드 원소입니다(그런 개인키를 찾는다는 건 해시/이산로그를 역산한다는
뜻이라 계산적으로 불가능). `CREATE2` 컨트랙트 주소는 **애초에 구조상** 어떤 키와도
무관합니다(계산식이 `keccak256(0xff ++ factory ++ salt ++ codeHash)`라 공개키가 이 계산에
전혀 등장하지 않음) — 그래서 이게 계산 불가능한 키 발견 단계 없이, 결정론적이고 PPID에
묶여있고 공개적으로 계산 가능하며 실제로(잔액을 갖고, 입금받을 수 있는) 작동하는 이더리움
주소를 얻는 유일한 방법입니다. 이 주소는 컨트랙트가 배포되기 전부터도 입금을 받을 수 있고
잔액 조회도 됩니다(이게 실제 프로덕션 계정추상화 지갑들이 쓰는 표준 "counterfactual
스마트컨트랙트 지갑" 패턴입니다).

**왜 PPID의 주소는 동시에 직접 자체 서명(hybrid 모드)도 안 되는가?**
이더리움 주소는 EOA(개인키 있음)거나 컨트랙트(코드 있음)거나 둘 중 하나로만 배타적으로
존재합니다 — 조건부로 둘 다일 수는 없습니다. 이건 명시적으로 검토했다가 불가능한 것으로
확인됐습니다.

**자금을 갖고 있지도 않은 별도 서명키(`pk_i`/`sk_i`)가 왜 필요한가?**
이건 **특정 payload를 승인하는 도구**입니다. `pi_pk_i` 증명만으로는 "나는 유효한
PPID/auth-token에 묶인 `pk_i`를 안다"는 것만 증명하지, 지금 어떤 특정 트랜잭션을 승인하는
건지는 아무것도 말해주지 않아서, 그것만으로는 다른 payload에 재사용될 수 있습니다.
`sk_i`로 payload의 해시에 별도로 서명하면 특정 승인을 특정 행위에 묶어줍니다. 두 검사가
**같은** `pk_i` 값을 가리켜야 합니다(컨트랙트가 이걸 명시적으로 대조합니다) — 안 그러면
서로 무관한 세션의 증명과 서명을 섞어서 쓸 수 있게 됩니다.

**왜 `pk_i`/`sk_i`는 secp256k1이고, 이 프로젝트 다른 곳에 쓰는 BabyJubJub가 아닌가?**
서로 무관한 두 가지 비용 축이 있습니다: Groth16 **회로 안에서** 서명을 검증하는 비용(여기선
BabyJubJub/EdDSA-Poseidon이 싸고 secp256k1은 아주 비쌉니다 — PS를 auth token에서 버린 것과
같은 이유), 그리고 Solidity 컨트랙트에서 **온체인으로 직접** 서명을 검증하는 비용(여기선
secp256k1이 네이티브 `ecrecover` 프리컴파일 덕에 싸고, BabyJubJub/P-256은 그에 준하는 저렴한
네이티브 경로가 없습니다). payload 서명은 (회로 안이 아니라) 컨트랙트 코드가 직접
검사하므로(다음 항목 참고), 여기서는 secp256k1이 맞는 선택입니다 — 회로 안이었다면 틀린
선택이었겠지만요. `pi_pk_i` 자체는 안 바뀝니다: `pk_i`는 원래부터 거기서 그냥 불투명한 해시
입력값(`tokenNonce = H(pk_i, max_height, rp_nonce)`)으로만 쓰였지 회로 안 곡선/서명 연산에
쓰인 적이 없어서, 곡선을 바꿔도 회로의 constraint 비용엔 전혀 영향 없습니다.

**왜 `PPID` 자체를 secp256k1 키로 만들어서 직접 자체 서명하게 하지 않는가?**
검토했다가 기각했습니다: `PPID = uid * rid * salt`는 기존 Mode 2 프로토콜 **전체**의
기반입니다(`pi_ppid.circom`, `pi_arid_i.circom`의 `auid_i = PPID * rpNonce`, IdP/RP 검증
체인 전체) — 이 유도 방식을 바꾸면 이 기능 범위를 넘어서 이미 배포된 것 전체에 breaking
change가 됩니다. 별도 파생값(`sk_addr = KDF(PPID)`)도 검토했지만, 특정 주소가 PPID로부터
KDF를 통해 정당하게 유도됐다는 걸 온체인에서 증명하려면 secp256k1 키 유도와 이더리움 주소
해시 계산을 Groth16 회로 **안에서** 시뮬레이션해야 해서, `CREATE2` 방식으로 피하려던 바로 그
"회로 안 secp256k1은 비쌈" 문제가 재등장합니다.

## 아키텍처

```
Wallet (wallet_agent.js, 로그인 이후)
  1. payload {to, value, data, nonce} 구성
  2. payloadHash = keccak256(payload)
  3. sig = sign(sk_i, payloadHash)              [secp256k1]
  4. proof = pi_pk_i 증명 생성                   [Groth16, 내부는 BabyJubJub]
       public: pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height
       hidden: arid_i, auid_i, r_token, chain_id, rp_nonce, S, R8x, R8y (서명 sigma_i의
               구성요소 — 아래 컴포넌트 섹션에서 왜 이 목록이 최초 설계보다 늘었는지 설명)

자금 있는 아무 EOA (가스비 담당, PPID/pk_i와 무관 — 데모는 Hardhat 테스트 계정)
  5. PPIDWalletFactory/PPIDWallet.execute(payload, sig, proof, pk_i, pk_IdP_x, pk_IdP_y, max_height) 호출

PPIDWallet 컨트랙트 (PPID의 CREATE2 주소에 위치; factory가 최초 사용 시 지연 배포)
  6. 순서대로 확인:
     a. payload.nonce == 컨트랙트가 저장 중인 nonce  (아니면 revert: 재사용)
     b. ecrecover(payloadHash, sig) == pk_i에서 뽑은 주소  (아니면 revert: 서명 무효)
     c. (pk_IdP_x, pk_IdP_y) == 컨트랙트가 저장 중인 신뢰된 pk_IdP  (아니면 revert: 신뢰
        안 된 IdP — 회로 자체는 어떤 IdP가 "신뢰됨"인지 모름; 컨트랙트가 압니다)
     d. pi_pk_i Groth16 증명이 (pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height)에 대해 검증됨
        (아니면 revert: 증명 무효)
     e. (b)와 (d)에서 쓰인 pk_i가 같음  (아니면 revert: pk_i 불일치)
     f. block.number <= max_height  (아니면 revert: 만료)
  7. nonce 증가 (아래 호출이 실패해도 — Error Handling 참고)
  8. 실행: (bool ok, ) = payload.to.call{value: payload.value}(payload.data)
```

## 컴포넌트

### `circuits/pi_pk_i.circom` (신규)
**계획 작성 중 실제로 회로를 짜서 컴파일하고, 유효한 witness와 조작된 witness 둘 다로
검증까지 마쳤습니다** (`circom` 2.1.6, `pot14_final.ptau`, non-linear constraints: 4820,
public inputs: 5, private inputs: 8 — 정상적으로 4820개 제약 전부 통과/거부 확인됨). 이
과정에서 최초 설계(브레인스토밍 단계에서 정한 것)의 hidden input 목록이 불완전했다는 걸
발견해서 여기서 정정합니다 — 아래가 실제로 컴파일·검증된 최종 버전입니다.

- Public input: `pk_i`, `pk_IdP_x`, `pk_IdP_y`, `PPID`, `max_height`. `pk_IdP`는 `EdDSAPoseidonVerifier`
  템플릿(`circuits/lib/eddsaposeidon.circom`, `Ax`/`Ay` 입력)이 실제 곡선 연산에 쓰는 값이라
  **필드 원소 하나가 아니라 좌표 두 개**입니다(`pk_i`와 달리 — `pk_i`는 회로 안에서 그냥
  Poseidon 해시 입력값으로만 쓰여서 지금처럼 하나의 값으로 뭉뚱그려도 됨). `pk_IdP`는
  회로에 하드코딩하지 않고 계속 public input으로 둬서, 신뢰된 IdP 키를 회로 재컴파일(새
  `.wasm`/`.zkey`) 없이 컨트랙트에 저장된 값만 바꿔서 교체(rotate)할 수 있게 합니다 —
  *회로*는 주어진 `pk_IdP`가 뭐든 그것에 대한 대수적 일관성만 증명하고, 신뢰 안 된 `pk_IdP`를
  쓴 증명을 거부하는 건 *컨트랙트*의 몫입니다(`PPIDWallet.execute`의 (c) 확인 참고).
- Hidden input(최초 설계보다 늘어난 부분 — `custom_idp.js`가 실제로 서명하는 6개 필드
  `[DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]`를 회로 안에서
  그대로 재구성해야 서명 검증이 되기 때문에, `auid_i`/`sigma_i`뿐 아니라 `arid_i`,
  `r_token`, `chain_id`도 다 필요합니다): `arid_i`, `auid_i`, `r_token`, `chain_id`,
  `rp_nonce`, 그리고 `sigma_i`의 세 구성요소 `S`, `R8x`, `R8y`.
- `DOMAIN_IDP_TOKEN`(=`valueToField('IDP_TOKEN')`, JS 쪽과 정확히 같은 값)은 회로 안에
  컴파일타임 상수로 하드코딩(`1351534856589225444686`) — 이 값은 `custom_idp.js`/`server.js`가
  이미 JS에서 계산하는 것과 동일한 함수로 미리 계산해서 박아넣은 것입니다.
- 조건 (전부 실제 컴파일된 회로에서 검증됨):
  1. `auid_i === PPID * rp_nonce`
  2. `r_token === Poseidon(pk_i, max_height, rp_nonce)` (기존 `tokenNonce` 공식과 동일)
  3. `msg = Poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id])`
  4. `EdDSAPoseidonVerifier(enabled=1, Ax=pk_IdP_x, Ay=pk_IdP_y, S, R8x, R8y, M=msg)` — 즉
     `SigVerify(pk_IdP, sigma_i) = True`
- (`docs/superpowers/specs/2026-07-14-eddsa-poseidon-auth-token-migration-design.md`의
  "Open questions for the follow-up trace sub-project" 참고 — 이 스펙이 그 질문들을
  해결합니다.)

### `contracts/PPIDWalletFactory.sol` (신규)
- `deploy(uint256 ppid) returns (address)` — `ppid`에 대한 `CREATE2` 주소를 계산하고,
  아직 안 배포됐으면 그 자리에 `PPIDWallet`을 배포, 어느 쪽이든 주소를 반환(멱등).
- 신뢰된 `pk_IdP` 값(`(x, y)` 좌표 두 개, 컨트랙트 자신이 갖고 있는 사본, 각 증명의 public
  `pk_IdP_x`/`pk_IdP_y` input과 대조됨 — Architecture (c) 확인 참고)과, 별도 배포된 `pi_pk_i` Groth16 verifier
  컨트랙트(snarkjs가 생성하는 표준 Solidity verifier 패턴) 참조를 갖고 있고, 이걸 각
  `PPIDWallet` 생성 시 넘겨줘서 모든 PPID 지갑이 중복 저장 없이 같은 신뢰 루트를
  공유하게 합니다.

### `contracts/PPIDWallet.sol` (신규)
- PPID당 하나씩 배포됨(factory를 통해, 최초 사용 시 지연 배포).
- 저장: `uint256 ppid`(생성 시 설정, 불변), `uint256 nonce`.
- `execute(Payload calldata payload, Signature calldata sig, Groth16Proof calldata proof, uint256 pk_i, uint256 pk_IdP_x, uint256 pk_IdP_y, uint256 max_height) external`
  — 위 Architecture의 확인 순서를 구현.
- `Payload { address to; uint256 value; bytes data; uint256 nonce; }`

### `wallet_agent.js` (수정)
- Step 8의 세션 키 생성을, `subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, ...)`에서
  secp256k1 키쌍(`@noble/curves/secp256k1` 사용, 이미 이 프로젝트 의존성)으로 변경.
- 로그인-이후 흐름을 위한 새 엔드포인트(예: `POST /submitTransaction`). `wallet_agent.js`
  자신은 로그인/로그인-이후 경계를 넘어서까지 상태를 유지하지 않습니다 — 기존 패턴과 동일
  (`/verifyIdPAuthToken`도 이미 `walletSubmission`/`business`를 서버 쪽에서 조회하지 않고
  요청 본문 필드로 받습니다) — 호출자(`client.js`, Step 11/12 이후 이미 자기 JS 상태에
  `currentSSOProof.business`/`walletSubmission`과 `walletReceivedIdPToken`을 갖고 있음)가
  요청 본문에 `{to, value, data, business, walletSubmission, idpToken}`을 실어 보냅니다.
  이 엔드포인트가 현재 nonce를 조회하고(배포된 `PPIDWallet`에 RPC 호출, 아직 미배포면 `0`),
  `payload`를 구성하고, `payloadHash`를 `sk_i`로 서명하고, 요청 본문의
  `arid_i`/`auid_i`/`r_token`/`chain_id`/`rp_nonce`/`sigma_i`(`business`/`walletSubmission`/
  `idpToken` 안에 이미 다 들어있는 필드들)로부터 `pi_pk_i` 증명을 생성합니다.

## 데이터 흐름

위 Architecture 섹션(1~8단계)에 이미 전부 명시돼 있습니다.

## 에러 처리

- `PPIDWallet.execute`의 여섯 가지 확인(nonce, 서명, 신뢰된 `pk_IdP`, 증명, `pk_i` 일치,
  만료) 각각 구체적이고 서로 다른 에러 메시지/커스텀 에러로 revert — 이 프로젝트의 기존
  관례(Mode 2의 각 검증 실패마다 뭉뚱그린 메시지가 아니라 구체적인 메시지를 씀)를
  따릅니다.
- **아래 `.call`이 실패해도 nonce는 증가시킵니다.** 이건 표준적인 스마트컨트랙트 지갑
  관례를 따른 겁니다(예: Gnosis Safe): 일단 payload가 검증되고 받아들여지면, 실행 결과와
  무관하게 그 nonce는 소진됩니다 — 공격자가 서명된-지금은-실패하는 payload를 (예를 들어
  대상 컨트랙트 상태가 악용 가능해질 때까지 기다렸다가) 반복 재시도하는 걸 막기 위함입니다.
  대가는, 정말로 일시적인 이유(예: 순간적인 잔액 부족)로 실행이 실패해도 그 nonce가
  영구히 소진돼서, wallet이 다음 nonce로 새 payload를 다시 서명해야 한다는 것입니다 —
  기존 스마트컨트랙트 지갑들이 이 문제를 다루는 방식과 일치하는, 받아들일 만한
  트레이드오프로 판단했습니다.
- `wallet_agent.js`의 새 증명 생성 경로는 Step 8/11 세션 데이터가 없으면 (기존
  `/generateStep8Proofs`의 검증 방식과 비슷하게) 크고 구체적으로 실패해야 합니다 — 이
  흐름은 로그인이 완료되기 전엔 실행될 수 없습니다.

## 테스트 계획

- `PPIDWallet`/`PPIDWalletFactory`에 대한 Hardhat 기반 Solidity 테스트: 정상 케이스(배포 +
  실행), 서명 조작, 증명 조작/무효, nonce 재사용(재사용 공격), 서명과 증명 간 `pk_i` 불일치,
  `max_height` 만료, 내부 `.call` 실패(nonce는 여전히 증가하는지 확인).
- `pi_pk_i.circom`에 대한 회로 레벨 테스트 — 이 프로젝트의 기존 `pi_arid_i`/`pi_ppid` 관례를
  따름(constraint 개수 확인, 유효한 witness는 통과, 조작된 witness는 거부).
- 엔드투엔드: 로컬 Hardhat 노드에서 전체 Mode 2 로그인(Step 1~15)을 실행한 뒤 실제
  트랜잭션 제출까지 배포된 컨트랙트를 통해 돌려봄 — EdDSA-Poseidon 마이그레이션의 Task 7을
  실제로 검증했던 방식을 그대로 따름.

## 후속 "B2 추적" 하위 작업을 위한 미해결 질문 (이 스펙 범위 아님)

- 제출된 트랜잭션에서 인가된 주체가 `uid`를 어떻게 복원하는지(PPT slide 4: "Group
  broadcast PPID... Query (σ, uid)" 기준) — 이 구현에서 "σ"가 구체적으로 뭘 가리키는지,
  IdP/RP가 어떤 기록을 보관해야 하는지, "인가됨"이 운영상 무슨 뜻인지(누가 어떤 절차로
  개봉(opening)을 요청할 수 있는지).
- B2가 `PPIDWallet.execute`가 온체인에 추가로 뭔가(예: 이벤트)를 기록해야 하는지, 아니면
  공유된 키로 조인되는 오프체인 IdP/RP 기록에 전적으로 의존할지(논문의
  `auth_digest_i` 기반 record-based opening 설계를 반영) 여부.
