# Mode 3 — 스냅 계정 번호: 한 시드의 여러 계정이 서로 다른 s_u·sk_u 를 갖게 (설계, 2026-11-12)

- 상태: 사용자 승인(2026-11-12, 대화 중 I-3 수정안 "①" 선택 → 번호 찾기 "0번 자동 + 번호 직접 입력" → 설계안 "ㅇㅋ").
- 배경(리뷰 I-3): 스냅 시드 유도 비밀(스펙 `2026-11-12-mode3-snap-derived-secrets-design.md`, 0.2.0)은 `snap_getEntropy` 에 고정 문자열만 넣어
  **같은 MetaMask(같은 SRP·같은 스냅 ID)면 IdP 계정이 달라도 s_u·sk_u 가 같다**. PPID 는 uid 가 들어가 RP 쪽에서는 갈리지만,
  등록 때 IdP 가 받는 pk_u 가 같아 IdP 가 두 계정을 같은 사람으로 묶을 수 있다. 속성 도구 salt 도 두 계정이 같다.
- 비범위: IdP(`cia.js`)·PPID 식·회로·컨트랙트(바꾸지 않는다), 파일·웹 모드, 다중 IdP, 0.2.0 등록의 이전(다시 등록한다 — §5).

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| K1 | 비밀을 **계정 번호 k** 마다 따로 유도한다: `snap_getEntropy` salt `zkd/mode3/s_u/v2/<k>`·`zkd/mode3/sk_u/v2/<k>`. k 는 0 이상 정수(10진, 상한 2^31−1). | 사용자 선택 ①. 번호가 다르면 s_u·sk_u 가 다르다 — IdP 가 pk_u 로 계정을 묶지 못한다. 유도 규칙이 바뀌므로 v1 → v2(같은 문자열에 다른 규칙을 얹지 않는다, 원 스펙 §2.2). |
| K2 | 번호 찾기는 **기록에 적어 둔 번호** 로 한다 — 후보 번호를 IdP 에 대 보지 않는다. | 후보마다 pk_u(또는 Google nonce 의 H(pk_u))를 IdP 에 보내면 다른 번호의 pk_u 가 곧 같은 사람의 다른 계정 키라 IdP 가 묶는다(고치려는 문제가 되돌아온다). 기록이 있으면 번호가 바로 나오므로 0번부터 맞춰 볼 필요가 없고, 기록이 없으면 맞춰 볼 기준값이 없다. |
| K3 | 기록이 없으면 **0번 자동 + 번호 직접 입력**. | 사용자 선택(2026-11-12). 계정을 하나만 쓰면 언제나 0번이라 자동이다. 대가: 다른 번호는 사용자가 기억해 넣는다(§5 한계). |
| K4 | 스냅은 **다음 가입 번호(`nextIndex`)** 를 상태에 두고 `reset`("스냅 초기화")에도 지우지 않는다. 새 가입을 저장하면 `max(nextIndex, k+1)` 로 올린다. | 같은 스냅으로 초기화 뒤 다른 계정을 만들면 번호가 저절로 달라진다. 번호는 비밀이 아니다. |

## 2. 스냅 (`snap-mode3`, 0.2.0 → 0.3.0)

### 2.1 유도 (`src/crypto.js`)
- `deriveRegistrationSecrets(index)`: `index` 가 정수 `0 ≤ index ≤ 2^31−1` 이 아니면 `bad_index` 로 던진다. salt 는 `ENTROPY_SALT_S_U_V2 = 'zkd/mode3/s_u/v2/'`, `ENTROPY_SALT_SK_U_V2 = 'zkd/mode3/sk_u/v2/'` 에 10진 `index` 를 붙인 문자열.
  s_u·sk_u 의 변환(`saltFromEntropy`·`skFromEntropy`)은 그대로. v1 상수는 지운다(v1 유도를 쓰는 곳이 없어진다).

### 2.2 상태
- `state.nextIndex`(정수, 없으면 0). `state.registration.index`(등록·보류 등록이 쓰는 번호).
- `reset`: `clearState()` 뒤 `{ nextIndex }` 만 다시 저장한다.
- `storeRegistration`: 저장에 성공하면 `nextIndex = max(nextIndex, registration.index + 1)`. 복구(`resume`)로 채운 등록도 같다 — 그 번호는 이미 쓰인 번호이므로.

### 2.3 RPC
| RPC | 동작 |
|---|---|
| `getSalt({ index? })` | `{ s_u, index }`. `index` 를 안 주면 `nextIndex`. 상태를 바꾸지 않는다. |
| `register({ uid, s_u?, index? })` | `index` 를 안 주면 `nextIndex`. 그 번호로 유도해 저장(`registration.index`). `s_u` 가 오면 그 번호의 유도값과 같을 때만 — 다르면 지금처럼 `salt_not_derived`. |
| `prepareRegister({ index? })` | `{ s_u, sk_u, index }`. 보류 등록이 있으면 그 비밀·번호를 그대로. 없으면 `index`(기본 `nextIndex`)로 유도해 보류 등록. |
| `setNextIndex({ index })` (새) | `nextIndex` 를 그 값으로. 범위 밖이면 `bad_index`. 등록 여부와 무관. 확인 창 없음(부를 수 있는 오리진은 여전히 `:5100` 뿐). |
| `getPublicInfo` | 지금 필드에 `index`(등록이 없으면 null)·`nextIndex` 를 더한다. |
- `showSalt`·`reset` 의 화면 문구는 그대로.

## 3. 번호가 흐르는 길

### 3.1 속성 도구 (`mode3/attr.html`, 아이디/비밀번호 가입)
- salt 칸 앞에 **"계정 번호"** 칸(정수). 화면을 열 때·"스냅에서 가져오기" 를 누를 때 비어 있으면 스냅의 `nextIndex` 로 채운다(`getSalt({})` 의 `index`).
  "스냅에서 가져오기" 는 칸의 번호로 `getSalt({ index })` 를 불러 salt 를 채운다.
- 기록(localStorage `mode3_attr_tool_v1`, 기록 version 2 유지)에 `index` 를 더한다. D20 자동 백업은 기록을 통째로 암호화하므로 따라온다.
  `index` 가 없는 기록(0.2.0 이전)은 열리지만 "시드로 복구할 수 없는 salt" 경고를 보인다(지금 경고와 같은 자리).
- 기록을 열 때의 경고 판정은 기록의 `index` 로 `getSalt({ index })` 한 값과 기록의 `s_u` 를 비교한다.

### 3.2 스냅 창 (`mode3/wallet.html`)
- `codeRegister`(아이디/비밀번호): 기록에 `index` 가 없으면 `attr_record_salt_not_derived` 로 멈춘다. 있으면 `getSalt({ index: rec.index })` 의 s_u 와 기록 s_u 를 비교(지금 검사)한 뒤
  `register({ uid, s_u: rec.s_u, index: rec.index })` → `/wallet/register` 에 `index` 를 함께 보낸다.
- `googleRegister`: `prepareRegister({})`(스냅의 `nextIndex`) → `/wallet/register` 에 `prep.index` 를 함께 보낸다(`prepareRegister` 가 `index` 를 돌려준다).
- 스냅만 비었을 때의 복구(`/wallet/register/resume` 두 곳): `/wallet/status` 의 `index` 로 `prepareRegister({ index })`. 에이전트 기록에 `index` 가 없으면(이 변경 이전 기록) 0 으로 본다.

### 3.3 에이전트 (`mode3_wallet_agent.js`)
- `/wallet/register`: 본문 `index`(선택, 정수 0..2^31−1 — 아니면 400 `bad_index`)를 등록 기록에 저장한다. 없으면 저장하지 않는다(파일 모드·웹 모드는 보내지 않는다).
- `/wallet/register/resume`: 그대로(s_u·sk_u 로 auid·pk_u 대조).
- `/wallet/status`: `index`(없으면 null)를 더한다.

### 3.4 zk 스냅 화면 (`localhost:5100`)
- 계정 탭 상세에 **"계정 번호: k"**, 그 아래 **"다음 가입 번호 [입력] [바꾸기]"** — `setNextIndex`. Google 가입이나 새 PC 에서 0번이 아닌 번호를 쓸 때 여기서 정한다.

### 3.5 결과
| 경우 | 쓰는 번호 |
|---|---|
| 같은 스냅에서 "스냅 초기화" 뒤 다른 계정 가입 | `nextIndex` 가 올라 있어 새 번호 — pk_u·s_u 가 다르다 |
| 스냅만 비었다(에이전트 기록 있음) | 에이전트 기록의 번호 → 같은 비밀 → 같은 PPID |
| 새 PC + 속성 도구 기록(또는 D20 백업) | 기록의 번호 |
| 새 PC + 기록 없음 | 0번(계정 하나면 맞다). 아니면 속성 도구 칸(아이디/비밀번호) 또는 zk 스냅 화면의 다음 가입 번호(Google)에 직접 |

## 4. 테스트
- **스냅 RPC**(`snap-mode3/test/rpc.test.mjs`, `snap` 그룹): 같은 시드라도 번호가 다르면 `getSalt`·`register`·`prepareRegister` 의 s_u·sk_u 가 다르다;
  같은 번호면 같다; `reset` 뒤에도 `nextIndex` 가 남는다; `storeRegistration` 뒤 `nextIndex` 가 오른다; `setNextIndex` 범위 검사(`bad_index`);
  번호와 어긋난 `s_u` 는 `salt_not_derived`; `getPublicInfo` 의 `index`·`nextIndex`.
- **에이전트**(`tests/test_mode3_wallet_agent.mjs`): `/wallet/register` 의 `index` 저장·`/wallet/status` 반환, 범위 밖 400 `bad_index`.
- **브라우저**(`browser` 그룹): 같은 시드 스텁으로 계정 A 가입 → 스냅 초기화·에이전트 비우기 → 계정 B 가입 → IdP 의 두 계정 pk_u 가 다르다;
  기존 복구 시나리오(스냅만 비었을 때, 새 PC + 기록, Google)가 같은 PPID 로 계속 통과; 속성 도구 번호 칸 → 다른 salt.
- 새 케이스는 고치기 전 코드에서 실패하는 것을 먼저 확인한다.

## 5. 대가·한계 (런북에 적는다)
- **스냅 0.3.0 재설치**가 필요하고, 0.2.0 으로 등록한 계정은 다시 등록해야 한다(유도 규칙 v1 → v2 — 같은 시드라도 값이 바뀐다). 데모 리셋을 권한다.
- 상태를 다 잃은 PC 에서 **새 계정**을 만들면 번호가 0 부터다 — 이미 쓴 번호를 고르면 그 계정과 키가 겹친다(I-3 이 그 경우에만 남는다). 번호는 사용자가 골라야 한다.
- 기록 없이 0번이 아닌 계정을 복구하려면 번호를 기억해야 한다.
- 원 스펙의 한계(스냅 ID 가 바뀌면 모든 유도값이 바뀐다)는 그대로.

## 6. 문서
- `docs/MODE3_DEMO.md`: 스냅 0.3.0 갱신, 계정 번호(속성 도구 칸·zk 스냅 화면의 다음 가입 번호), §5 한계.
- 원 스펙(`2026-11-12-mode3-snap-derived-secrets-design.md`) 머리에 "유도 규칙은 계정 번호 스펙(v2)으로 대체" 한 줄.
