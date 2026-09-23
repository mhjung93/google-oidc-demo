# Mode 2 후속 작업: PPIDWallet Sponsored(Paymaster) Execution

## 상태

사용자 승인 완료(2026-07-20), 아직 구현 안 됨. 논문의 "IMPLEMENTATION AND SCOPE" 섹션에 막 추가한
"C. ADDRESS ABSTRACTION: PPID-DERIVED ACCOUNTS" 소절(`documents/PairCT_research_article_20260706_092133_with_figures_final43.docx`)에서
"future work: account abstraction 일반화(batched/sponsored execution)"로 예고한 항목 중 sponsored execution을 먼저 다룬다.

## 배경

`contracts/PPIDWallet.sol`은 이미 address abstraction(`PPIDWalletFactory.computeAddress(ppid)`가 CREATE2로
`ppid`에서 결정론적 주소를 계산)과 최소한의 account abstraction(`execute()`가 nonce + ECDSA 서명 + `pi_pk_i` 온체인
Groth16 증명 + `max_height` 만료 검사로 트랜잭션을 인가)을 갖추고 있다. 그런데 현재 `client.js`
(`submitPPIDTransaction` 클릭 핸들러, `client.js:456-507`)는 `wallet_agent.js`의 `/submitTransaction`이 만든
`{deploy, to, data}`를 받아서 **사용자 자신의 MetaMask**로만 전송한다 — `wallet_agent.js`에 가스비를 낼 서명 키가
없기 때문이라는 주석이 코드에 남아 있다(`wallet_agent.js:590-592`).

설계 브레인스토밍 중 다음을 확인했다:
- `PPIDWallet.execute()`는 `msg.sender`를 전혀 검사하지 않는다 — 서명(`sig`)과 ZK 증명(`pi_pk_i`)만으로 인가가
  끝나므로, **컨트랙트는 이미 아무나(제3자 relayer 포함) 대신 보내도 안전하게 설계돼 있다.** 즉 sponsored execution은
  컨트랙트 변경 없이 순수 오프체인 배선 문제다.
- 과거(5일 전) 메모리에 있던 "PPID 주소가 매 로그인마다 안정적이려면 `k_user`로부터 영구 서명키를 유도해야 한다"는
  아이디어는 스코프에서 제외했다 — 주소 안정성은 CREATE2(ppid)로 이미 해결돼 있고, `pk_i`가 세션마다 fresh한 것은
  오히려 cross-service linkability 방지를 위해 의도된 동작이다(`0c65265` 커밋 참고).
- `pi_pk_i.circom` 안에서 `pk_i`는 Poseidon 해시에 들어가는 평범한 필드 원소일 뿐, Baby Jubjub 곡선 점으로 다뤄지지
  않는다. EdDSA-Poseidon 서명 검증은 오직 `pk_IdP`(IdP 키)에 대해서만 이루어진다. 따라서 "secp256k1 ↔ Baby Jubjub
  커브 매칭 문제"도 애초에 실재하지 않았던 것으로 보고 스코프에서 제외했다.
- 이 두 항목(`k_user` 유도, 커브 매칭)이 스코프에서 빠졌으므로, 방금 논문에 넣은 "open prototype questions" 문장은
  더 이상 정확하지 않다 — 이번 설계가 끝난 뒤 별도로 논문 문구를 수정해야 한다(이 스펙의 책임 범위 밖, 후속 작업으로
  기록만 해둠).

## 범위

**포함:**
- `server.js`: 새 엔드포인트 `POST /api/mode2/relay_transaction` — `{deploy?, to, data}`를 받아서 로컬 Hardhat
  노드의 기본 unlock 계정으로 대신 전송한다.
  - 실제 전송 전에 `eth_call`로 동일한 payload를 시뮬레이션해서, 서명/증명이 잘못됐거나 `max_height`가 지난
    요청은 실제 가스를 쓰지 않고 즉시 거부한다.
  - `deploy`가 있으면(PPIDWallet이 아직 배포 안 됐으면) 배포 트랜잭션을 먼저 보내고 영수증을 기다린 뒤 `execute`
    트랜잭션을 보낸다 — `client.js`의 기존 MetaMask 흐름(`client.js:482-502`)과 같은 순서.
  - 서명키를 새로 관리하지 않는다 — 로컬 Hardhat 노드가 이미 unlock해서 펀딩해둔 계정 주소를 `from`으로 써서
    `eth_sendTransaction`을 호출한다(노드가 서명을 대신 해줌).
- `client.js` + `index.html`: 기존 "Send PPID Transaction"(MetaMask) 버튼 옆에 "Send via Sponsor" 버튼을
  추가한다. 클릭하면 `wallet_agent.js`의 `/submitTransaction` 응답을 그대로 새 relay 엔드포인트로 전달하고, 반환된
  tx hash를 화면에 표시한다.

**명시적으로 범위 밖:**
- `wallet_agent.js`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol`, `circuits/pi_pk_i.circom` —
  전부 변경 없음.
- 실제 테스트넷/메인넷에서 쓸 private-key 기반 relayer(현재는 로컬 Hardhat의 unlock 계정에만 의존, 실체인에는
  적용 불가) — future work.
- gas 상환(reimbursement) 메커니즘(사용자가 나중에 sponsor에게 gas 비용을 갚는 방식) — future work.
- relayer 남용 방지(rate limiting, 요청자 인증 등) — `custom_idp.js`에 이미 알려진 데모 위생 이슈들과 같은
  분류로 남겨두고 이번 스코프에서 다루지 않는다. (`eth_call` dry-run이 "실제 가스 낭비"는 막아주지만, relay
  엔드포인트 자체에 대한 요청 스팸까지 막지는 못한다 — 이 잔여 위험은 알고 있고 의도적으로 미루는 것이다.)
- 논문의 "open prototype questions" 문장 수정 — 이 스펙 승인 후 별도 작업으로 처리.

## 핵심 설계 결정

**왜 relayer 서명키를 새로 안 만드는가?**
데모가 로컬 Hardhat 노드에서만 돈다는 전제(`MODE2_ETH_RPC_URL=http://127.0.0.1:8545`, `scripts/redeploy_ppid_factory.cjs`도
같은 전제로 `hre`를 직접 씀)를 그대로 따른다. Hardhat 로컬 네트워크는 기본 계정들을 이미 unlock한 채로 펀딩해두므로,
`server.js`가 `eth_sendTransaction`을 호출하면 노드가 알아서 서명해서 보내준다. 새 private key 관리, `.env` 추가,
서명 로직 추가가 전혀 필요 없다 — 최소 변경 원칙에 맞고, 이미 이 프로젝트가 데모 스코프를 명시적으로 인정하고 있는
관례(`MODE2_FLOW.md`의 하드코딩 데모 계정 등)와도 일치한다.

**왜 컨트랙트를 안 바꿔도 되는가?**
`PPIDWallet.execute()`는 이미 `msg.sender`를 검사하지 않고, 서명(`ecrecover(payloadHash, sig) == pk_i`)과
`pi_pk_i` 증명만으로 인가를 끝낸다. 즉 "누가 보냈는지"가 아니라 "무엇이 서명·증명됐는지"로 안전성이 결정되는
구조라, 이미 컨트랙트 자체가 relayer-agnostic하다. sponsored execution은 이 컨트랙트의 기존 속성을 오프체인에서
그대로 활용하는 것뿐이다.

**왜 전송 전에 `eth_call` dry-run을 넣는가?**
`server.js`가 대신 gas를 내는 구조이므로, 잘못되거나 만료된 payload를 그대로 `eth_sendTransaction`하면
실제로 revert하는 트랜잭션에 대해서도 gas가 소모된다(전형적인 paymaster 남용 벡터). `eth_call`은 같은
payload를 온체인 상태 변경 없이 시뮬레이션만 하므로, 통과하는 요청만 실제로 전송하면 이 낭비를 거의 공짜로
막을 수 있다. 요청 스팸 자체(악의적으로 dry-run만 계속 호출)까지는 막지 못하지만, 그건 "명시적으로 범위 밖"에
이미 남겨뒀다.

## 테스트 및 검증

- 새 엔드포인트에 대한 단위 테스트는 이 프로젝트의 기존 관례(Mode 2 관련 상태는 라이브 검증으로 확인)를 따라
  생략하고, 라이브 검증으로 확인한다.
- 라이브 검증 시나리오:
  1. 로그인(Step 1-15) 완료 후 "Send via Sponsor" 클릭 → PPIDWallet이 아직 배포 안 된 첫 로그인이면 배포 tx가
     먼저 전송되는지, 그 다음 execute tx가 전송되는지 확인.
  2. 반환된 tx hash가 실제로 성공적으로 마이닝됐는지(`eth_getTransactionReceipt`로) 확인.
  3. `wallet_agent.js`가 만든 `to`/`data`를 일부러 깨뜨린 요청(예: 서명을 임의로 바꾼 payload)을 보내서,
     실제 `eth_sendTransaction` 전에 `eth_call` 단계에서 거부되는지(= 실제 tx가 체인에 안 올라가는지) 확인.
  4. MetaMask 경로("Send PPID Transaction")와 sponsor 경로("Send via Sponsor")가 서로의 nonce를 깨뜨리지
     않는지 — 같은 `PPIDWallet`에 대해 두 경로를 번갈아 써도 `execute()`의 nonce 체크가 정상 작동하는지 확인.

## Self-Review

- **플레이스홀더 검사**: 없음.
- **범위 일관성**: "포함" 목록의 두 항목(server.js 엔드포인트, client.js/index.html UI)이 서로의 인터페이스(요청/응답
  JSON 모양)를 명시적으로 공유하도록 기술함. "범위 밖" 목록은 브레인스토밍 대화에서 나온 제외 결정과 1:1로 대응됨.
- **모순 검사**: `wallet_agent.js`/컨트랙트/회로를 "변경 없음"이라고 배경과 범위 양쪽에서 일관되게 명시함.
