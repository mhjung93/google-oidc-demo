# Mode 2 후속 작업: RP 페이지 트랜잭션 제출 UI

## 상태

사용자 승인 완료(2026-07-16), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

B1(`docs/superpowers/specs/2026-07-15-ppid-transaction-submission-design.md`)이 `wallet_agent.js`의 `/submitTransaction` 엔드포인트를 만들었지만, 이걸 실제로 호출해서 온체인에 보내는 UI는 아직 없다.

먼저 "Snap Home Page에 버튼을 두고 RP 페이지는 완전히 무관하게"라는 방향으로 설계를 진행했으나(`docs/superpowers/specs/2026-07-16-snap-home-page-transaction-submission-design.md`, 폐기됨), 검증 중 **MetaMask Snap은 `eth_sendTransaction`을 직접 호출할 수 없다**(`endowment:ethereum-provider`가 read 전용이라는 공식 제약)는 게 확인되어 그 경로 자체가 성립하지 않았다.

이어진 논의에서,애초에 "RP FE가 트랜잭션 제출에 관여하면 안 된다"는 원칙을 재검토했다: 이 프로젝트가 숨기는 건 `uid`(사용자의 IdP 쪽 정체성)이지, "트랜잭션이 일어난다"는 사실 자체가 아니다. `to`/`value`/`data`(트랜잭션 내용)는 RP 자신의 서비스와 상호작용하는 내용이므로 RP가 이를 아는 건 자연스럽다(OpenSea가 자신이 판매하는 NFT의 구매 트랜잭션 내용을 아는 것과 동일한 구도). RP가 트리거한다고 해서 `uid`가 새롭게 노출되지는 않는다 — `uid` 은닉은 B1의 `pk_i`(uid 아님)/zk 증명 구조가 담당한다. 그래서 원래 첫 제안대로 RP 페이지(`client.js`)에 버튼을 두는 방향으로 확정했다.

## 범위

**포함:**
- `wallet_agent.js`: `/submitTransaction`의 응답 형태를 바꿔서, 클라이언트가 `PPIDWallet`의 ABI를 몰라도 되게 한다 — `{ to: walletAddress, data: encodedExecuteCalldata }`를 직접 반환. 대상 `PPIDWallet` 주소(`PPID_WALLET_FACTORY_ADDRESS`의 `computeAddress(ppid)`)와 현재 온체인 `nonce`(대상 주소의 `nonce()`)를 서버가 직접 RPC로 조회해서 채운다(호출자가 더 이상 `currentNonce`를 안 보내도 됨).
- `client.js`: Step 15 완료 후 "트랜잭션 보내기" 버튼 추가. 클릭 시 `/submitTransaction` 호출(기존 `business`/`rpNonce`/`idpToken`을 그대로 실어 보냄, B1 설계 그대로) → 응답의 `{to, data}`를 그대로 `window.ethereum.request({method:'eth_sendTransaction', ...})`에 전달 → 결과(tx hash) 표시.

**명시적으로 범위 밖:**
- Snap(`snap/`) 변경 — 이번 설계는 Snap을 전혀 건드리지 않는다.
- 받는 사람/금액을 사용자가 입력하는 폼 — 데모용 고정값 사용.
- B2 추적(`trace_transaction`) 호출 UI — 별도.
- `circuits/pi_pk_i.circom`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol` 수정.
- 가스비 지불 프라이버시(릴레이어 등) — B1 스펙에서 이미 명시적으로 보류된 범위, 그대로 유지(브라우저에 연결된 MetaMask 계정이 가스를 낸다).

## 핵심 설계 결정과 기각된 대안들

**왜 Snap Home Page 경로를 버렸는가?**
검증 결과 Snap의 `ethereum` 전역(`endowment:ethereum-provider`)은 read 전용이라 `eth_sendTransaction`을 아예 호출할 수 없다(MetaMask 공식 문서 확인). 트랜잭션을 실제로 보내려면 반드시 일반 웹페이지가 필요한데, 어차피 웹페이지가 필요하다면 RP 페이지를 쓰는 게 훨씬 단순하다.

**왜 "RP FE는 무관해야 한다"는 원래 원칙을 재검토했는가?**
이 프로토콜이 숨기는 건 `uid`뿐이다. RP는 `auid`(자기 로컬 가명 핸들)를 이미 알고, 트랜잭션의 `to`/`value`/`data`는 애초에 RP 서비스와 상호작용하는 내용이라 RP가 아는 게 새로운 프라이버시 손실이 아니다. RP가 트랜잭션 제출을 트리거하는 것과 RP가 `uid`를 알게 되는 것은 서로 다른 문제다 — 후자를 막는 건 여전히 B1의 zk 증명 구조가 담당한다.

**왜 `wallet_agent.js`가 ABI 인코딩과 `nonce` 조회까지 다 하는가?**
Snap 설계 때 이미 검증했던 이유가 그대로 적용된다: ABI/calldata 지식을 한 곳(`wallet_agent.js`)에만 두면 `client.js`가 컨트랙트 세부사항을 몰라도 되고, 프론트엔드에 `ethers` 같은 무거운 의존성을 새로 들여올 필요가 없다. `currentNonce`를 호출자가 넘기지 않고 서버가 직접 조회하게 바꾼 것도 같은 이유 — 호출자가 최신 온체인 상태를 추적할 필요가 없어진다(B1 원래 설계보다 더 단순해짐, 의도적인 계약 변경).

**왜 받는 사람/금액이 고정값인가?**
이 기능의 핵심은 "PPID로 온체인 강제 검증을 통과하는 트랜잭션을 낼 수 있다"는 메커니즘 자체를 보여주는 것이지, 실제 상품 기능(무엇을 살지 등)을 만드는 게 아니다. 폼 UI는 범위 밖.

**`PPIDWallet`이 아직 배포 안 됐을 수 있다는 점을 어떻게 처리하는가?**
B1 설계상 `PPIDWallet`은 `CREATE2`로 지연 배포된다 — 최초 사용 전에는 그 주소에 컨트랙트 코드가 없다(counterfactual). 코드가 없는 주소로 `execute()` calldata를 보내면 아무 로직도 실행되지 않고 조용히 아무 일도 안 일어난다(revert도 안 남). `wallet_agent.js`는 서명용 키(`sk_i`)만 갖고 있고 가스비를 낼 온체인 서명 키가 없어서, 배포 트랜잭션 자체를 스스로 보낼 수 없다 — 결국 배포도 `execute()`와 마찬가지로 브라우저의 MetaMask(가스 지불자)가 보내야 한다. 그래서 `/submitTransaction`은 `walletAddress`에 코드가 있는지(`eth_getCode`) 확인해서, 없으면 응답에 `deploy: { to: factoryAddress, data: deployCalldata }`를 포함시킨다. `client.js`는 `deploy`가 있으면 그 트랜잭션을 먼저 보내고 채굴을 기다린 뒤, `execute()` 트랜잭션을 보낸다(두 번의 `eth_sendTransaction` 호출, MetaMask 승인 팝업도 두 번).

## 아키텍처

```
[Step 15 완료 후, client.js]
  "트랜잭션 보내기" 버튼 표시

[버튼 클릭]
  client.js: wallet_agent.js의 POST /submitTransaction 호출
    body: { to: <데모 고정 수신 주소>, value: '0', data: '0x',
             business: currentSSOProof.business, rpNonce, idpToken: walletReceivedIdPToken }
    (currentNonce는 더 이상 안 보냄 — 서버가 직접 조회)

  wallet_agent.js:
    1. business에서 PPID 추출 -> PPID_WALLET_FACTORY_ADDRESS.computeAddress(ppid) RPC 조회
       -> walletAddress
    2. walletAddress.eth_getCode 조회 -> 코드 없으면 factory.deploy(ppid) calldata도 준비
    3. walletAddress.nonce() RPC 조회(코드 없으면 0으로 간주) -> currentNonce
    4. payload = {to, value, data, nonce: currentNonce} 구성, sk_i로 서명
    5. pi_pk_i 증명 생성
    6. PPIDWallet.execute(...) calldata를 ABI 인코딩
    7. { deploy: {to: factoryAddress, data: deployCalldata} | null,
         to: walletAddress, data: encodedExecuteCalldata } 응답

  client.js:
    window.ethereum.request({method:'eth_requestAccounts'}) -> from 주소 확보
    (deploy가 있으면) window.ethereum.request({method:'eth_sendTransaction',
      params:[{from, to: factoryAddress, data: deployCalldata}]}) -> 채굴 대기
    window.ethereum.request({method:'eth_sendTransaction',
      params:[{from, to: walletAddress, data: encodedExecuteCalldata}]})
    -> MetaMask 표준 승인 팝업 (자동, deploy 있으면 총 2번)
    -> 승인되면 tx hash 반환, 화면에 표시
```

## 컴포넌트

### `wallet_agent.js` (수정)
- **신규 설정**: `PPID_WALLET_FACTORY_ADDRESS` 환경변수(배포된 `PPIDWalletFactory`의 주소) — `MODE2_ETH_RPC_URL`과 같은 위치에서 읽는다. 지금은 이 정보를 아는 컴포넌트가 전혀 없다(B1 검증 때는 임시 스크립트가 수동으로 배포/전달했다).
- `/submitTransaction`: 요청 본문에서 `currentNonce`를 제거(더 이상 필수 아님). 기존 `getOrCreateSessionKey()`/증명 생성 로직은 그대로 유지하되, 다음을 추가:
  - `PPID_WALLET_FACTORY_ADDRESS`의 `computeAddress(ppid)`를 `eth_call`로 조회해 `walletAddress` 확보(이미 있는 `rpcCall()` 헬퍼 + `ethers`의 `Interface`로 인코딩/디코딩).
  - `eth_getCode`로 `walletAddress`에 코드가 있는지 확인. 없으면 `factory.deploy(ppid)`의 calldata를 준비해두고, `currentNonce`는 `0`으로 간주(아직 컨트랙트가 없으니 `nonce()` 호출 없이).
  - 코드가 있으면 `walletAddress`의 `nonce()`를 `eth_call`로 조회해 `currentNonce` 확보.
  - `payload.nonce`에 이 값을 사용.
  - 응답을 `{ deploy: {to, data} | null, to: walletAddress, data: encodedExecuteCalldata }`로 변경(기존 `payload`/`sig`/`proofA/B/C`/`pk_i`/`pk_IdP_x`/`pk_IdP_y`/`max_height` 필드는 더 이상 응답에 포함하지 않음 — `execute()` calldata 안에 이미 인코딩되어 있음).

### `client.js` (수정)
- Step 15(`ssoMetadata`/로그인 완료 표시) 이후에 "트랜잭션 보내기" 버튼과 결과 표시 영역 추가.
- 버튼 클릭 핸들러: `wallet_agent.js`의 `/submitTransaction`을 기존 패턴(`X-Wallet-Agent-Token` 포함)으로 호출 → `eth_requestAccounts`로 `from` 확보 → 응답에 `deploy`가 있으면 그 트랜잭션을 먼저 `eth_sendTransaction`으로 보내고 영수증(`eth_getTransactionReceipt`)을 기다림 → 이어서 `{to, data}`(execute)를 `eth_sendTransaction`으로 전송 → 결과(tx hash 또는 에러) 표시.

## 데이터 흐름

아키텍처 섹션에 이미 명시.

## 에러 처리

- `/submitTransaction`이 `PPID_WALLET_FACTORY_ADDRESS`를 설정 안 한 채 호출되면 명확한 500 에러("PPID_WALLET_FACTORY_ADDRESS not configured").
- `computeAddress`/`nonce()` RPC 조회가 실패하면(체인 연결 안 됨 등) 502 + 원인 메시지.
- `eth_sendTransaction`을 사용자가 MetaMask에서 거부(reject)하면 client.js가 그 에러를 잡아 "사용자가 거부함" 표시(트랜잭션이 실제로 안 나간 것과 구분).
- MetaMask가 연결된 계정에 가스비가 없으면 `eth_sendTransaction` 자체가 실패 — client.js는 그 에러 메시지를 그대로 보여준다(데모 환경에서는 Hardhat 테스트 계정을 MetaMask에 임포트해서 가스를 대야 함, 이 설정 자체는 테스트 단계에서 안내).

## 테스트 계획

- `wallet_agent.js`의 `/submitTransaction` 응답이 실제로 유효한 `execute()` calldata를 인코딩하는지(디코딩해서 원래 값들과 일치하는지) 단위 확인.
- 로컬 Hardhat 노드 + 배포된 `PPIDWalletFactory`/`PPIDWallet` 대상으로, 실제 로그인(Step 1~15) → 버튼 클릭 → MetaMask 승인 → 온체인 `execute()` 성공까지 라이브 확인(MetaMask 확장 프로그램 설치 + Hardhat 테스트 계정 임포트 필요 — 브라우저 조작이 필요해 자동화 불가, 사용자 확인 필요).
- MetaMask에서 거부했을 때 client.js가 에러를 올바르게 표시하는지 확인.

## 후속 작업 (이 스펙 범위 밖)

- 받는 사람/금액을 사용자가 입력하는 폼
- B2 추적 호출을 위한 별도 UI
- 가스비 지불 프라이버시(릴레이어 서비스)
