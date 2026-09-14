# Mode 3 데모 — 기동과 시연

설계: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`
UI 스펙: `docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md`

Mode 2 데모(:3000/:4000/:5001)와 **공존**한다. 포트·상태 파일이 다르고 코드를 공유하지 않는다.

## 프로세스와 포트

| 프로세스 | 포트 | 명령 | 상태 파일 |
|---|---|---|---|
| hardhat 노드 | :8545 | `npx hardhat node` | — |
| CIA | :4100 | `node cia.js` | `cia_state.json`, `cia_keys.json` |
| 지갑 에이전트 | :5100 | `node mode3_wallet_agent.js` | `mode3_wallet_state.json` |
| RP | :3100 | `node mode3_rp.js` | (메모리) |

## 처음 한 번: 배포와 `.env`

0. `bash scripts/build_mode3_circuit.sh pot21_final.ptau` — `build/mode3/` 의 zkey·vkey·wasm 을 한 세트로 만든다(수 분).
   회로를 바꾼 뒤에는 반드시 다시 돌린다. 다른 기계에 `build/` 를 복사해 뒀다면 그것도 다시 옮긴다.
1. `npx hardhat node` (다른 터미널에 상주).
2. `CIA_ADMIN_SECRET=<아무 문자열> node cia.js` — 처음 기동에서 `cia_keys.json`을 만든다. `curl -s 127.0.0.1:4100/cia/public_keys`의 `ethAddress`를 적어 두고 종료한다.
3. `CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` — `RevocationLog`를 배포하고 CIA 주소에 1 ETH를 넣는다. 출력의 `CIA_LOG_ADDRESS=0x…`를 `.env`에 추가한다.
4. `.env`에 `CIA_ADMIN_SECRET=<2의 값>`도 넣는다. (세 서버 모두 `dotenv`로 `.env`를 읽는다. `CIA_*`·`MODE3_*` 키는 이 데모만 쓴다.)

선택 env: `CIA_TTL_SECONDS`(credential 만료, 기본 3600), `CIA_CHAIN_IDS`(발급을 허용할 폐기 체인 id 목록, 기본은 RPC 의 chainId).

선택: 운영이라면 RP의 `pk_CIA`를 TOFU가 아니라 env로 박는다 — `curl -s 127.0.0.1:4100/cia/public_keys`의 `pk_CIA.x/y`를 `MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`에.

## 매번: 기동 순서

```
npx hardhat node                # 이미 떠 있으면 생략
node cia.js                     # :4100
node mode3_wallet_agent.js      # :5100
node mode3_rp.js                # :3100 (기동 시 CIA 에서 pk_CIA 를 받아 고정 — CIA 가 먼저 떠 있어야 한다)
```

페이지: 지갑 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, CIA 관리자 `http://127.0.0.1:4100/admin`, CIA 사용자 `http://127.0.0.1:4100/account`.

RP 페이지는 반드시 `127.0.0.1`로 연다 — 지갑 에이전트의 CORS 허용 오리진이 `http://127.0.0.1:3100`(`MODE3_RP_ORIGIN`)이라 `localhost`로 열면 지갑 호출이 막힌다.

## 시연 각본

| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 1 | 지갑 | 등록 (`12345` / `password123`, 속성 4칸은 기본값 그대로) | `등록됨` |
| 2 | RP | Mode 3 로그인 | `새 발급=true`, 로그인 성공, PPID |
| 3 | RP | 로그인 (다시) | `캐시 히트=true`, 증명 0 ms, 같은 PPID |
| 4 | 관리자 | 계정 폐기 → 게시 | `published:true`, epoch +1 |
| 4′ | 사용자 페이지 → 관리자 | (4 대신) `12345` / `password123` 로 내 계정 폐기 → 관리자가 게시 | `disabled:true`, `inserted` 에 리프, 이후 5~8 동일 |
| 5 | RP | "동기화 생략" 체크 → 로그인 | 거절 `stale_root` |
| 6 | RP | 체크 해제 → 로그인 | 지갑이 폐기를 감지해 재발급 시도 → `account_disabled` |
| 7 | 관리자 | 복구 | `disabled:false` |
| 8 | RP | 로그인 | `새 발급=true`, 성공, **PPID 가 2 와 같다** (설계 §6.6) |

1~8 은 `tests/test_mode3_demo_stack.mjs`(HTTP)와 `tests/test_mode3_e2e.mjs`(라이브러리)로, 4′ 은 HTTP 테스트로만 고정돼 있다.

속성 4칸은 사용자가 고르는 값이고 CIA 는 보지 못한다(설계 2026-09-14 §2). credential 은 발급 시각 + 1시간에 만료되며, 지갑 상태 페이지에 `exptime` 으로 보인다.

4′ 은 관리자 없이 사용자가 스스로 폐기하는 경로다(설계 §6.5.1). 인증은 계정 비밀번호이고 지갑 키가 아니다 —
장치를 잃은 사용자에게 지갑 키는 없고 공격자에게는 있기 때문이다. 처리와 게시는 4 와 같고, 복구는 여전히 관리자만 한다.

## 하지 말 것 / 재시연

- **옛 상태 파일(`version: 1`, `max_height`)을 새 CIA 에 물리지 않는다.** CIA 가 기동을 거부한다 — 재시연 세트로 새로 시작한다.
- **`cia_state.json`을 지우지 않는다.** 체인의 `RevocationLog.root`와 어긋나 지갑의 `syncRevocationTree`가 root 불일치로 전원을 막는다(Mode 2의 `idp_state.json`과 같은 이유). CIA 는 기동 시 로컬 트리를 온체인 root 와 대조해 어긋나면 `root 불일치`로 기동을 거부하므로, 지웠다면 아래 재시연 세트를 통째로 다시 한다.
- 재시연은 **한 세트로만**: hardhat 노드 재시작 → 위 "처음 한 번" 2~3(재배포, `.env`의 `CIA_LOG_ADDRESS` 갱신) → `cia_state.json`·`mode3_wallet_state.json` 삭제 → 세 서버 재시작. `cia_keys.json`은 그대로 둬도 된다 — 게시 서명이 로그 주소를 덮으므로 같은 키로 재배포해도 옛 로그의 게시를 새 로그에 재생할 수 없다.
- 데모 계정은 `cia.js`의 `DEMO_ACCOUNTS`(`testuser`/`password123` → uid 12345, `alice`/`alicepw` → uid 67890). 지갑 에이전트는 한 계정만 등록한다.
- `CIA_ADMIN_SECRET` 없이 띄운 CIA 에서 사용자 페이지의 폐기를 누르지 않는다 — 자기 폐기는 시크릿 없이도 되지만 복구(`set_disabled`)와 게시는 503 이라 계정이 되돌릴 수 없게 비활성으로 남는다.

## 테스트

- `bash scripts/run_tests.sh chain` — 격리 스택(임시 포트)으로 전 구간. :8545 와 `build/mode3/`의 `pi_cred` zkey·vkey 만 있으면 된다.
