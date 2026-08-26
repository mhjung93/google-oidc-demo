# Mode 2 후속 작업: PPID 유도 공식을 곱셈에서 Poseidon 해시로 전환

## 상태

사용자 승인 완료(2026-07-17), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

현재 `PPID = uid * rid * salt (mod p)`는 유한체 위의 평문 곱셈이다. 유한체의 모든 0이 아닌 원소는 역원을 가지므로, 이 관계는 대수적으로 가역적이다: `PPID`, `rid` 중 아무거나 알면 나머지는 나눗셈(모듈러 역원)으로 그대로 복원된다.

이게 실제로 문제가 되는 이유는 두 값 모두 공개되기 때문이다:
- `PPID`는 `PPIDWallet.execute()`의 Groth16 public signal로 온체인에 그대로 노출된다.
- `rid`는 `server.js`의 `/api/mode2/rp_info`가 인증 없이 그대로 반환한다.

따라서 서로 다른 두 RP에서 나온 온체인 `PPID` 값과 각 RP의 공개 `rid`를 관찰한 제3자는 `PPID_1 * rid_2 == PPID_2 * rid_1 (mod p)`를 검산해서, `uid`/`salt`를 몰라도 두 트랜잭션이 같은 지갑(같은 `uid*salt`)에서 나왔는지 판별할 수 있다. 이는 PairCT가 보장하려는 cross-RP unlinkability를 정확히 깨는 방향이다.

논문(`documents/` 최신 draft)의 formal 구성은 애초에 이 값을 `auid = H("PairCT.auid", uid, rid, salt_u)`로, 즉 해시로 정의한다. 논문 자체도 프로토타입의 `PPID = uid * rid * salt` 관계를 "validation/inspection 용도일 뿐, 배포용 프라이버시 구성으로 오인하면 안 된다"고 명시적으로 경고하고 있다. 이번 작업은 그 경고를 실제로 반영해서, 프로토타입의 `PPID` 유도 공식 자체를 논문의 `auid` 정의와 통일하는 것이다.

## 범위

**포함:**
- `circuits/pi_ppid.circom` — `ppid = uid * rid * salt` 제약을 `ppid = Poseidon(uid, rid, salt)` 제약으로 교체.
- `circuits/pi_arid_i.circom` — 내부적으로 `ppid`를 유도하는 부분(현재 곱셈 2개, `auid_i === ppid * rp_nonce`의 입력으로만 쓰임)을 동일하게 Poseidon 해시로 교체.
- `wallet_agent.js` — Step 8 핸들러의 `ppid` 계산 한 줄(`(uidField * rid * saltField) % FIELD_PRIME`)을 이 파일에 이미 있는 관용구(`poseidon.F.toObject(poseidon([...]))`)로 교체.
- `client.js` — Step 14 검증부의 설명 주석(`ppid = uid * rid * salt for some hidden uid/salt`)을 새 공식에 맞게 수정. 검증 로직 자체는 변경 없음(증명 검증이 회로에 위임되는 구조라 자동 반영).
- `tests/test_pi_arid_i_no_rid.js` — 로컬에서 `auid_i`를 만들 때 쓰는 `ppid` 계산을 새 회로와 일치하게 Poseidon으로 교체.
- 신규 회귀 테스트: 같은 `uid`/`salt`, 서로 다른 `rid` 두 개로 `ppid`를 계산해서, 곱셈 방식이면 성립했을 `ppid1 * rid2 == ppid2 * rid1` 검산이 해시 방식에서는 더 이상 성립하지 않음을 확인.
- `circuits/pi_auid.circom`과 그 빌드 산출물(`build/mode2/pi_auid.*`) 삭제 — `pi_ppid.circom`이 이제 동일한 일을 하므로 중복.
- `pi_ppid`, `pi_arid_i` 두 회로만 재컴파일 + 재키생성(`scripts/build_mode2_circuits.sh`의 기존 패턴, `pot14_final.ptau` 재사용).
- 검증을 위한 로컬 서버 재시작(`custom_idp.js`, `wallet_agent.js`) 및 `PPIDWalletFactory` 재배포(아래 "알려진 부작용" 참고).

**명시적으로 범위 밖:**
- `PPID`/`ppid`/`auid` 등 변수·필드·컨트랙트 이름 변경 — 공식만 바꾸고 이름은 그대로 유지(사용자 결정).
- `auid_i = PPID * rp_nonce` 블라인딩 단계 — 그대로 유지(사용자 결정). 이 단계도 곱셈이라 유사한 대수적 성질을 가질 수 있으나, 이번 작업과는 별개 사안으로 남겨둔다.
- `circuits/pi_pk_i.circom` — `PPID`를 opaque public input으로만 받고 그 유도 방식을 검증하지 않으므로 변경 불필요(확인 완료).
- `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol`, `contracts/PiPkIVerifier.sol` — 전부 `ppid`를 opaque `uint256`으로만 다루므로 변경/재배포 불필요(단, `custom_idp.js` 재시작으로 인한 `pk_IdP` 변경 때문에 `PPIDWalletFactory`는 별도 이유로 재배포됨 — 아래 참고).
- `server.js` — `pi_ppid`/`pi_arid_i` 증명을 전혀 검증하지 않으므로 변경 불필요(확인 완료).
- `npm run zk:ptau` — 기존 `pot14_final.ptau`(2^14=16384 제약)가 새 회로 크기(약 261, 약 522)를 충분히 커버하므로 재실행 불필요.

## 핵심 설계 결정과 기각된 대안들

**왜 이름은 그대로 두고 공식만 바꾸는가?**
`ppid`/`PPID`라는 이름은 `wallet_agent.js`, `client.js`, 온체인 컨트랙트(`PPIDWallet`/`PPIDWalletFactory`) 전반에 퍼져 있다. 논문 용어(`auid`)에 맞춰 전면 리네이밍하면 컨트랙트 재배포·인터페이스 변경까지 번지는 훨씬 큰 작업이 된다. 지금 필요한 건 "값이 대수적으로 가역적이지 않게 만드는 것"이지 이름 통일이 아니므로, 최소 변경 원칙에 따라 공식만 바꾼다.

**왜 `pi_auid.circom`을 재사용하지 않고 `pi_ppid.circom`을 수정하는가?**
`pi_auid.circom`은 최초 커밋부터 있었지만 실제 플로우(`wallet_agent.js`/`client.js`/`custom_idp.js`) 어디에서도 참조되지 않는 미사용 레거시 회로다. 반면 `pi_ppid.circom`은 이미 `wallet_agent.js`의 `fullProve` 호출, `client.js`의 검증 로직, 파일명 규칙(`pi_ppid_vkey.json` 등) 전체에 배선돼 있다. `pi_ppid.circom` 내부 로직만 바꾸면 이 모든 배선을 그대로 재사용할 수 있으므로, 새로 `pi_auid.circom`을 배선하는 대신 기존 `pi_ppid.circom`을 수정하고 중복된 `pi_auid.circom`은 삭제한다.

**왜 `pi_pk_i.circom`/컨트랙트/`server.js`는 안 건드리는가?**
세 곳 모두 코드를 직접 읽어서 확인했다: `pi_pk_i.circom`은 `PPID`를 그냥 public input으로 받아 `auid_i === PPID * rp_nonce`만 검사할 뿐, `uid*rid*salt` 유도 자체는 재검증하지 않는다. 컨트랙트들은 `ppid`를 `uint256` opaque 값으로만 다룬다(CREATE2 salt, Groth16 public input 전달용). `server.js`는 애초에 `pi_ppid`/`pi_arid_i` 증명을 검증하는 코드가 없다(PS/EdDSA 인증서 검증과는 별개). 따라서 이 세 곳은 `PPID`의 내부 유도 방식이 바뀌어도 영향받지 않는다.

**Poseidon 입력 순서는 어떻게 고정하는가?**
`Poseidon(uid, rid, salt)`의 세 입력 순서는 `pi_ppid.circom`, `pi_arid_i.circom`의 내부 유도, `wallet_agent.js`의 JS 계산 세 곳에서 정확히 동일해야 한다(순서가 다르면 서로 다른 해시값이 나와서 증명 검증이 조용히 실패한다 — EdDSA-Poseidon 인증 토큰 메시지 구성 때 이미 겪은 것과 같은 종류의 함정). 기존에 있던(미사용) `pi_auid.circom`이 이미 `hasher.inputs[0]=uid, [1]=rid, [2]=salt` 순서를 쓰고 있으므로, 이 관례를 그대로 따라 세 곳 모두 `[uid, rid, salt]` 순서로 통일한다.

**왜 `zk:ptau`를 다시 안 돌리는가?**
`scripts/build_mode2_circuits.sh`가 이미 `pot14_final.ptau`(2^14=16384) 하나를 `pi_arid_i`(265 제약), `pi_ppid`(2 제약), `pi_pk_i`(4820 제약) 전부에 공유해서 쓰고 있다. 새 회로 크기(Poseidon(3) 추가로 `pi_ppid`는 약 261, `pi_arid_i`는 약 522로 추정)도 이미 이 ptau가 커버하는 `pi_pk_i`의 4820보다 작으므로, 기존 ptau를 그대로 재사용한다.

## 알려진 부작용: `custom_idp.js` 재시작과 `PPIDWalletFactory` 재배포

`pi_arid_i_vkey.json`은 `custom_idp.js`가 시작할 때 한 번만 읽어서 메모리에 올린다(요청마다 다시 읽지 않음). 새로 생성된 vkey를 반영하려면 `custom_idp.js` 재시작이 필요하다.

그런데 `custom_idp.js`의 EdDSA 키쌍(`idpEdDSAKeys`)은 디스크에 저장되지 않고 프로세스 시작마다 새로 랜덤 생성된다(이번 세션 초반에 실측 확인됨). 재시작하면 `pk_IdP`가 바뀌는데, `PPIDWallet`/`PPIDWalletFactory`는 배포 시점의 `pk_IdP`를 `immutable`로 고정해서 신뢰하므로, 온체인 트랜잭션까지 라이브로 재테스트하려면 `PiPkIVerifier`(변경 없음, 그대로)와 `PPIDWalletFactory`를 새 `pk_IdP`로 다시 배포해야 한다. 이건 이번 작업이 유발하는 문제가 아니라, `custom_idp.js` 재시작이 항상 갖는 기존 성질이며, 이번 세션에서 이미 한 번 같은 패턴으로 처리한 적 있다.

## 테스트 및 검증

- `node --check`로 수정한 모든 JS 파일 구문 검사.
- `tests/test_pi_arid_i_no_rid.js` 재실행 — 새 회로에서도 "정상 witness 성공 / 변조된 `arid_i` 거부"가 그대로 성립하는지 확인.
- 신규 cross-RP unlinkability 테스트 실행 — 곱셈 방식이면 성립했을 교차검산이 해시 방식에서는 실패함을 확인.
- 로컬 서버(`custom_idp.js`, `wallet_agent.js`) 재시작 후, 브라우저로 로그인 → 트랜잭션 제출까지 실제 라이브 재테스트(사용자 수행).
- 테스트 종료 후 이번에 새로 띄운 포트를 정리.
