# Mode 2 후속 작업: 로그인마다 새 세션 서명키(pk_i/sk_i) 생성

## 상태

사용자 승인 완료(2026-07-19), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

Wallet-IdP 통신을 OIDC와 프로토콜 수준으로 비교하다가 발견한 문제다. `wallet_agent.js`의 세션 서명키(`pk_i`/`sk_i`, secp256k1)가 `wallet_state.json`에 영구 저장돼서 **모든 로그인, 모든 RP에서 계속 같은 값이 재사용**되고 있다.

논문의 formal protocol은 이렇게 설계하지 않았다 — lightweight variant는 `sk_i = KDF("PairCT.key", k_user, auid, sid_i, ctx_i)`로, `sid_i`(매 세션 RP가 새로 발급하는 challenge)가 입력에 들어가서 **세션마다 `sk_i`/`pk_i`가 달라지도록** 설계돼 있다.

`pk_i`는 IdP에게 가는 `pi_i^IdP`와 RP에게 가는 `pi_i^RP` 양쪽에 평문 public input으로 들어가고, 온체인 `pi_pk_i`에도 평문으로 노출된다. 지금처럼 고정돼 있으면:
- IdP가 `PPID`/`arid_i`/`auid_i`를 못 봐도, 같은 `pk_i`가 반복되는 것만으로 "이 세션들은 같은 지갑"임을 알 수 있다(세션 간 상관관계 추적).
- 서로 다른 RP(또는 온체인 관찰자)가 `pk_i`만 대조해도 같은 지갑인지 바로 알 수 있다 — 논문 Property 5(Cross-service unlinkability)가 막으려는 바로 그 속성을 프로토타입이 실제로는 못 지키고 있다.

## 범위

**포함:**
- `wallet_agent.js`: `getOrCreateSessionKey()`(디스크 영속화, `wallet_state.json`의 `mode2SessionKey` 필드 사용)를 두 함수로 분리.
  - `generateNewSessionKey()` — Step 8 핸들러(`/generateStep8Proofs`)에서만 호출. 매번 새 `secp256k1` 키쌍을 생성해서 **메모리 전용** 모듈 레벨 변수에 저장하고 반환.
  - `getCurrentSessionKey()` — `/submitTransaction`에서 호출. 메모리에 있는 현재 키를 그대로 읽어서 반환. 키가 없으면(로그인 없이 바로 호출된 경우) 명확한 에러를 던진다.

**명시적으로 범위 밖:**
- `wallet_state.json`의 `salt`/`agentToken` 필드 — 그대로 영속화 유지, 손대지 않는다.
- 기존 `wallet_state.json` 파일에 남아있을 수 있는 `mode2SessionKey` 필드 — 더 이상 안 읽으므로 그냥 죽은 데이터가 된다. 별도 마이그레이션/삭제 코드는 추가하지 않는다(최소 변경).
- `circuits/*.circom`, `contracts/*.sol`, `custom_idp.js`, `client.js`, `server.js` — 이 변경과 무관, 손대지 않는다.

## 핵심 설계 결정

**왜 온체인 `PPIDWallet.execute()`가 이 변경과 호환되는가?**
컨트랙트는 배포 시점에 `pk_i`를 고정하지 않는다 — 매 `execute()` 호출마다 그 호출의 Groth16 증명이 담고 있는 `pk_i`를 `ecrecover`로 재검증한다(코드 확인 완료). 즉 서로 다른 방문(로그인)에서 서로 다른 `pk_i`를 쓰더라도, 각 트랜잭션이 자기 완결적인 증명 체인(그 방문의 로그인에서 나온 `auid_i`/`PPID`와 일치하는 `pk_i`)을 갖고 있으면 온체인 검증은 그대로 통과한다.

**왜 디스크가 아니라 메모리에만 두는가?**
이 키는 "한 방문(로그인→트랜잭션 제출) 동안만" 일관되면 되고, `wallet_agent.js`는 그 방문 내내 떠 있는 프로세스라 메모리로 충분하다. 디스크에 남기면 프로세스가 재시작돼도 옛날 키가 부활해서 "매 로그인마다 새로 생성"이라는 목표를 다시 깨뜨릴 수 있다.

**왜 `mode2SessionKey` 필드를 적극적으로 지우지 않는가?**
새 코드가 이 필드를 아예 안 읽으므로, 남아있어도 아무 영향이 없다. 지우는 로직을 추가하는 건 이번 목적(세션마다 새 키)과 무관한 범위 확장이라 최소 변경 원칙에 따라 생략한다.

## 테스트 및 검증

- `node --check wallet_agent.js`로 구문 검사.
- 이 함수 자체를 검증하는 기존 단위 테스트는 없음(이 프로젝트에서 `wallet_agent.js`의 이런 종류의 상태는 항상 라이브 검증으로 확인해왔음, 새 테스트를 억지로 만들지 않음).
- 라이브 검증: 서버 재시작(코드 변경 반영 위해 `wallet_agent.js`만 재시작하면 됨, 회로/키 변경 없으므로 factory 재배포 불필요) 후, 로그인을 두 번 해서 매번 다른 `pk_i`(주소)가 나오는지 확인. 그리고 한 번의 방문 안에서는 로그인 때 쓰인 `pk_i`와 트랜잭션 제출 때 쓰이는 `pk_i`가 같은지(트랜잭션이 정상적으로 성공하는지로 간접 확인) 확인.
