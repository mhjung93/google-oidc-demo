# Mode 3 — 폐기 트리(RCL) 증분 동기화 설계: 체크포인트 + 델타

**상태: 초안. 사용자 검토 대기.**
작성 2026-09-23. 브레인스토밍 결정(사용자): ①체크포인트는 지갑 상태 파일이 아니라 **별도 캐시 파일** `mode3_wallet_rcl.json`(상태 파일 버전 7 유지),
②델타를 적용한 root 가 컨트랙트 root 와 다르면 **전체 재생 1회**로 복구하고 그래도 다르면 throw(지금의 fail-closed 유지),
③리프가 새로 붙었을 때만 캐시를 쓴다, ④동시 `sync()` 는 진행 중인 호출 하나를 공유한다.
2026-09-22 결정(메모리): range 샤딩(샤드 인덱스가 Cf_u 상위 비트를 누설)과 SMT 전환(회로 2배·부트스트랩 누설)은 채택하지 않는다. IMT 는 그대로 —
옛 리프의 next 포인터가 바뀌므로 옛 서브트리를 "얼릴" 수 없고, 델타 재생이 정답이다.

기반 문서: `2026-09-18-mode3-onchain-execution-design.md`(§7.2 지갑의 트리 재구성), `2026-09-21-mode3-two-tier-credential-design.md`(RCL 리프 = Poseidon(4, Cf_u)),
`2026-08-23-baar-revocation-design.md`(IMT v2). 이 문서는 **지갑 에이전트가 폐기 트리를 얻는 방법**만 바꾼다. 회로·컨트랙트(`RevocationLog`)·CIA·서비스·증명 형식·
공개 입력은 바뀌지 않는다. 비멤버십 증명의 의미(§7.2: "CIA 없이도 체인 이벤트만으로 트리를 재구성할 수 있다")도 그대로다 — 캐시는 그 재구성을 빠르게 할 뿐이다.

---

## 1. 무엇이 달라지는가

| | 지금 (`lib/mode3_wallet.js:138 syncRevocationTree`) | 이 문서 |
|---|---|---|
| 호출 시점 | 로그인·재검증·트랜잭션 **매 호출**(`mode3_wallet_agent.js:331, 460, 558`) | 같음 |
| 이벤트 조회 | `queryFilter(Revoked, 0, head)` — 창세기부터 전부 | `lastSyncedBlock+1 .. head` 만 |
| 트리 구성 | `buildIMTv2(depth, 전체 리프)` — 매번 O(N log N) Poseidon | 메모리의 IMT 에 델타 리프만 `insert` |
| 재시작 | 창세기부터 재생 | 캐시 파일의 리프를 순서대로 `insert` 해 복원(O(N) Poseidon 1회), 그 뒤 델타 |
| 검증 | 재구성 root ≠ 컨트랙트 root → throw | 델타 root ≠ 컨트랙트 root → **전체 재생 1회** → 그래도 다르면 throw |
| 영속 | 없음 | `mode3_wallet_rcl.json`(공개 데이터만) |
| 반환 | `{ tree, root, epoch, head }` | 같음(+`mode`). `proveSession` 은 root 출처만 바뀐다(§5) |

**왜:** 로그인마다 창세기부터 getLogs + 전체 리프 Poseidon 재해싱이다. 리프 1k 면 수 초가 된다(2026-09-11 리뷰 R8 에서 보류한 항목).
IMT v2 는 `insert()` 가 증분이고 `getLeaves()` 로 삽입 순서 리프를 꺼낼 수 있으며, **같은 순서로 넣으면 같은 root** 다(`buildIMTv2` 는 `insert` 의 반복이다 — `lib/imt_v2.js:379-389`).
따라서 체크포인트는 "삽입 순서 리프 목록"만으로 충분하다.

---

## 2. 구조와 파일

| 파일 | 역할 |
|---|---|
| `lib/mode3_rcl_sync.js` (신규) | `createRevocationSync({ provider, logAddress, cacheFile, log? })` → `{ sync(), stats(), reset() }` |
| `lib/mode3_wallet.js` | `syncRevocationTree(provider, logAddress)` **그대로 유지** — 전체 재생 원시 연산. 부트스트랩과 fallback 이 부른다. `buildCredentialProof` 의 `revRoot` 는 `w.root` 로(§5). 기존 테스트 7개(`test_mode3_wallet/e2e/rp/demo_stack/cia_*`)는 변경 없음 |
| `mode3_wallet_agent.js` | 기동 시 `const rcl = createRevocationSync(...)` 하나. 세 호출부의 `syncRevocationTree(provider, LOG_ADDRESS)` → `rcl.sync()`. `proveSession` 의 응답 `root`·캐시 키는 `proved.revRoot`(§5). `GET /wallet/status` 에 `rcl: stats()` 추가(리프 수·lastSyncedBlock·마지막 동기화 방식) |
| `mode3_wallet_rcl.json` (런타임 생성) | 캐시. 경로 `MODE3_WALLET_RCL_CACHE`(기본: 상태 파일과 같은 디렉터리의 `mode3_wallet_rcl.json`). `.gitignore` 에 추가 |
| `tests/test_mode3_rcl_sync.mjs` (신규) | §6 단위 테스트. `scripts/run_tests.sh` **chain** 그룹 |
| `scripts/bench_mode3_rcl_sync.mjs` (신규), `results/mode3_rcl_sync_<YYYYMMDD>.md` | §7 벤치 |
| `docs/MODE3_DEMO.md` | "하지 말 것 / 재시연" 에 캐시 파일 한 줄, "테스트" 에 새 파일 |

### 2.1 `createRevocationSync` 인터페이스

```js
// lib/mode3_rcl_sync.js
export function createRevocationSync({ provider, logAddress, cacheFile, log = console.warn })
// 반환:
//   sync()  → Promise<{ tree, root: bigint, epoch: bigint, head: bigint, mode: 'delta'|'restore'|'bootstrap'|'fallback' }>
//             (앞 네 필드는 syncRevocationTree 와 같은 의미·타입. mode 는 관측용 — proveSession 은 읽지 않는다)
//   stats() → { leaves: number, lastSyncedBlock: bigint|null, lastMode: string|null, cacheFile: string }
//   reset() → 메모리 트리와 캐시 파일을 버린다(테스트·운영 복구용). 다음 sync() 는 부트스트랩
```

`provider` 는 에이전트가 이미 `{ cacheTimeout: -1 }` 로 만든다(`mode3_wallet_agent.js:49`). 그 밖의 provider 로 부를 때는 `syncRevocationTree` 주석의 250 ms 캐시 주의가 그대로 적용된다.

---

## 3. 동기화 알고리즘

```
sync():
  if inFlight: return inFlight                                   # §5 동시성
  inFlight = run(); try { return await inFlight } finally { inFlight = null }

run():
  head ← BigInt(provider.getBlockNumber())
  [onchainRoot, epoch] ← log.root({blockTag: head}), log.epoch({blockTag: head})     # eth_call 2회 — 지금과 같음

  if 메모리 트리 없음:
      c ← 캐시 파일 읽기 (§4). 유효하면:
          tree ← createRevocationTree(); for v of c.leaves: tree.insert(v)             # 'restore'
          lastSyncedBlock ← c.lastSyncedBlock
      아니면:
          return bootstrap(head, onchainRoot, epoch)                                     # 'bootstrap'

  if head < lastSyncedBlock:                                       # 체인 리셋(hardhat 재기동 등)
      경고; return bootstrap(...)

  if head > lastSyncedBlock:
      events ← log.queryFilter(Revoked, lastSyncedBlock + 1, head)
      for e of events (블록·로그 순서대로): for l of e.args.leaves: tree.insert(BigInt(l)); appended++
  # head == lastSyncedBlock 이면 조회 생략(같은 블록을 두 번 훑지 않는다)

  if tree.getRoot() ≠ BigInt(onchainRoot):
      경고("델타 root 불일치 — 전체 재생으로 복구")
      return bootstrap(...)                                        # 'fallback'. bootstrap 안에서도 다르면 throw

  lastSyncedBlock ← head
  if appended > 0: 캐시 쓰기 (§4)
  return { tree, root, epoch, head, mode: 'delta' }

bootstrap(head, onchainRoot, epoch):
  메모리 트리·캐시 파일 폐기
  { tree, root, epoch, head } ← syncRevocationTree(provider, logAddress)      # 창세기부터. root ≠ 컨트랙트면 throw (기존 fail-closed)
  lastSyncedBlock ← head; 캐시 쓰기
  return { ..., mode }
```

- **하트비트**(리프가 빈 `Revoked`, `cia.js:514 publishNow({heartbeat:true})`)는 델타 0. `epoch` 은 매 호출 컨트랙트에서 읽으므로 그대로 갱신된다.
- **head 고정**: 이벤트·root·epoch 모두 같은 `head` 블록에 고정한다(지금과 같음). `syncRevocationTree` 를 부르는 bootstrap 은 자기 `head` 를 다시 읽는데, 그 값이 더 클 수 있다 — 반환하는 `head` 는 bootstrap 의 것이다(더 새 스냅샷이므로 무해).
- **fallback 은 1회**: `run()` 안에서 bootstrap 은 최대 한 번이고, bootstrap 의 root 불일치는 `syncRevocationTree` 가 throw 한다. 재시도 루프 없음.
- **이벤트 순서**: `queryFilter` 결과는 (blockNumber, logIndex) 오름차순이다. CIA 가 한 트랜잭션에 여러 리프를 넣을 때(`leaves` 배열) 배열 순서가 곧 CIA 의 삽입 순서이며, 이는 `syncRevocationTree` 가 지금 기대는 것과 같은 규약이다.

---

## 4. 캐시 파일

```json
{ "version": 1, "logAddress": "0x…", "chainId": "31337", "lastSyncedBlock": "1234", "epoch": "57", "root": "…10진…", "leaves": ["…10진…", "…"] }
```

- 리프는 IMT `getLeaves()` 의 삽입 순서 그대로(anchor 제외). 전부 **공개 데이터**(체인 calldata 에 이미 있는 값) — snap 모드의 "상태 파일에 비밀 없음" 불변식과 무관하다.
- **유효 조건**(모두 만족해야 복원): `version === 1`, `logAddress` 가 현재 값과 같음(대소문자 무시), `chainId` 가 `provider.getNetwork()` 와 같음, `leaves` 가 10진 문자열 배열, `lastSyncedBlock` 이 10진 문자열. 하나라도 틀리면 경고 후 무시 → 부트스트랩.
- 복원 뒤 `tree.getRoot()` 가 파일의 `root` 와 다르면 파일 손상으로 보고 경고 후 부트스트랩(§3 의 델타 root 검사보다 먼저).
- **쓰는 시점**: 리프가 새로 붙었을 때와 bootstrap 뒤에만. 리프 변화 없는 로그인마다 쓰지 않는다. 따라서 파일의 `lastSyncedBlock` 은 메모리보다 뒤처질 수 있고, 재시작 뒤 그 블록부터 다시 훑는 구간은 리프가 없는 것이 확실하므로(있었다면 그때 썼다) 결과가 같다.
- **원자적 쓰기**: 같은 디렉터리의 임시 파일에 쓰고 `rename`. 쓰기 실패는 경고만(다음 sync 가 다시 시도) — 캐시는 정확성에 관여하지 않는다.
- 캐시는 언제 지워도 안전하다. 지우면 다음 `sync()` 가 부트스트랩한다. `reset()` 이 같은 일을 한다.

---

## 5. 동시성

로그인·재검증·트랜잭션 라우트가 같은 순간 `sync()` 를 부르면 같은 IMT 객체에 두 실행의 `insert` 가 섞일 수 있다(`insert` 하나는 끊기지 않지만, `run()` 의 RPC `await` 사이에 다른 실행이 끼어든다). `sync()` 는 **진행 중인 호출 하나를 공유**한다: 이미 돌고 있으면 새 실행을 만들지 않고 그 promise 를 돌려준다. 동시 요청은 같은 `head` 스냅샷을 받으므로 의미도 맞다(두 요청이 각각 head 를 읽으면 오히려 서로 다른 블록을 볼 수 있다).

`proveSession` → `buildCredentialProof` 는 `synced.tree` 로 비멤버십 증인을 만든다. 같은 IMT 객체를 여러 요청이 공유하면 **증인을 만든 뒤 다음 `sync()` 의 `insert` 가 끼어드는** 새 경합이 생긴다. 실제 코드로 따져 보면:

- `insert()` 본문에는 `await` 가 없다(`lib/imt_v2.js:194-226`) — 삽입 하나는 한 틱 안에 끝나고 중간에 끊기지 않는다.
- `getNonMembershipWitness()` 도 본문에 `await` 가 없고, **자기가 기준으로 삼은 root 를 결과에 싣는다**(`lib/imt_v2.js:324-347`, `w.root`).
- 그런데 `buildCredentialProof` 는 증인을 받은 뒤 `encryptTag` 를 `await` 하고 나서 `tree.getRoot()` 를 **다시 읽어** 공개 입력 `revRoot` 로 쓴다(`lib/mode3_wallet.js:171-190`). 그 사이에 `insert` 가 들어오면 증인의 root 와 공개 입력 root 가 어긋나 `fullProve` 가 실패하거나 검증이 깨진다.

따라서 이 문서는 두 줄을 바꾼다:
1. `buildCredentialProof` 는 `revRoot` 로 `tree.getRoot()` 대신 **`w.root`**(증인이 계산된 root)를 쓴다 — 공개 입력·반환값 모두. 증명은 자기 증인과 항상 일관된다.
2. `proveSession` 은 응답의 `root` 와 증명 캐시 키로 `synced.root` 대신 **`proved.revRoot`** 를 쓴다. `sync()` 와 증인 생성 사이에 리프가 붙었다면 증명은 더 새 root 에 대한 것이고, 서비스의 root 나이 검사에는 더 유리하다. `synced.root` 는 폐기 여부 사전 검사(`tree.has(leaf)`)에만 남는다.

이 두 줄이 없으면 캐시를 공유하는 순간 동시 로그인·재검증에서 간헐적 증명 실패가 생긴다. 지금 코드는 호출마다 새 트리를 만들어 이 경합이 없었을 뿐이다.

---

## 6. 테스트 (`tests/test_mode3_rcl_sync.mjs`, chain 그룹)

hardhat(:8545)에 `RevocationLog` 를 새로 배포하고, 테스트가 CIA 키로 직접 `publishRoot` 를 부른다(기존 `test_mode3_wallet.mjs` 의 방식). 캐시 파일은 임시 디렉터리.

1. **델타 = 전체**: 리프 3개 게시 → `sync()`(bootstrap) → 리프 2개 더 게시 → `sync()`(delta). root 가 `syncRevocationTree` 의 root 와 같고 `mode === 'delta'`.
2. **조회 범위**: provider 를 감싸 `eth_getLogs` 의 `fromBlock` 을 기록. 두 번째 `sync()` 가 `lastSyncedBlock+1` 부터만 부른다. 같은 head 에서 세 번째 `sync()` 는 `eth_getLogs` 를 부르지 않는다.
3. **하트비트**: `publishRoot(같은 root, epoch+1, [])` → `sync()` 가 리프 0·`epoch` 갱신·캐시 파일 미변경(mtime).
4. **복원**: 새 `createRevocationSync`(같은 캐시 파일) → 첫 `sync()` 가 `mode === 'restore'`, root 일치, `eth_getLogs` 는 캐시의 `lastSyncedBlock+1` 부터.
5. **캐시 무효**: (a) `logAddress` 다른 파일 (b) JSON 손상 (c) `version: 0` → 각각 `mode === 'bootstrap'`, 경고 1회.
6. **델타 불일치 → fallback**: 캐시 파일의 리프 하나를 바꿔 둔 뒤 새 인스턴스로 `sync()` → 복원 root ≠ 파일 root 로 잡히면 §4 규칙이 먼저 걸리므로, 이 케이스는 **파일 root 도 함께 위조**해 복원은 통과시키고 델타 후 컨트랙트 root 와 어긋나게 만든다 → `mode === 'fallback'`, 결과 root 는 컨트랙트와 일치, 경고 1회, 캐시 파일이 올바른 리프로 다시 써짐.
7. **fail-closed**: 컨트랙트 `root()` 를 가로채 다른 값을 돌려주는 provider 스텁 → `sync()` 가 throw(메시지에 "root"), 캐시 파일 미변경.
8. **동시성**: `Promise.all([sync(), sync(), sync()])` 의 세 결과가 같은 `tree` 객체·같은 `head`, `eth_getLogs` 호출 1회.
9. **체인 리셋**: 캐시의 `lastSyncedBlock` 을 head 보다 크게 써 둠 → `mode === 'bootstrap'`, 경고.

기존: `syncRevocationTree` 를 쓰는 7개 테스트는 변경 없음. 데모 스택·e2e 는 에이전트 경로가 캐시를 지나므로 그대로 통과해야 하고, `test_mode3_wallet_agent.mjs` 에 "재시작 뒤 캐시 복원으로 로그인·재검증 성공(상태 `rcl.lastMode === 'restore'`)" 한 케이스를 더한다.

---

## 7. 벤치

`scripts/bench_mode3_rcl_sync.mjs`: 리프 N ∈ {0, 100, 1000} 를 게시한 뒤 (a) 전체 재생 `syncRevocationTree` (b) 캐시 복원 첫 `sync()` (c) 델타 `sync()`(리프 1개 추가 후) (d) 델타 0 `sync()` 의 벽시계 시간을 각 5회 중앙값으로. 결과는 `results/mode3_rcl_sync_<YYYYMMDD>.md` 에 새 파일로(기존 결과 덮어쓰지 않음). 기존 벤치(`scripts/bench_mode3_onchain.mjs`)의 표 형식을 따른다.

---

## 8. 오류·운영

| 상황 | 동작 | 사용자에게 |
|---|---|---|
| 캐시 파일 없음/손상/다른 컨트랙트 | 경고 1줄, 부트스트랩 | 첫 로그인이 느릴 뿐 |
| 델타 root 불일치 | 경고 1줄, 전체 재생 1회 | 그 로그인이 느릴 뿐 |
| 전체 재생도 불일치 | throw(기존 메시지) → 라우트가 지금처럼 `sync_failed` 계열 오류 | 기존과 같음 |
| 캐시 쓰기 실패(권한·디스크) | 경고, 계속 진행 | 없음 |
| 체인 리셋(head < lastSyncedBlock) | 경고, 부트스트랩 | 없음 |

운영 메모(`docs/MODE3_DEMO.md`): `RevocationLog` 를 재배포하면 캐시는 `logAddress` 불일치로 자동 무시된다 — 지울 필요 없음. hardhat 을 재기동해 블록이 되감기면 체인 리셋으로 잡힌다. 강제로 처음부터 재생하려면 `mode3_wallet_rcl.json` 을 지우거나 `POST /wallet/rcl/reset`(같은 오리진, 데모용)을 부른다.

---

## 9. 범위 밖 · 결정된 것 · 열린 것

- **범위 밖**: CIA 의 트리(자체 상태 `cia_state.json`)는 무관. 인덱서 스냅샷으로 부트스트랩하는 선택지는 넣지 않는다(YAGNI — 데모 규모에서 전체 재생 1회는 충분히 빠르다). 회로·컨트랙트 무변경.
- **결정**(2026-09-23, 사용자): 캐시는 별도 파일(상태 파일 v7 유지); 불일치 시 전체 재생 1회 후 throw; 리프가 붙었을 때만 캐시 쓰기; 동시 호출은 in-flight 공유.
- **열린 것**: 없음. (`POST /wallet/rcl/reset` 은 §8 운영 편의용으로 넣되, 구현 부담이 크면 `reset()` 만 두고 라우트는 뺀다 — 계획 단계에서 정한다.)
