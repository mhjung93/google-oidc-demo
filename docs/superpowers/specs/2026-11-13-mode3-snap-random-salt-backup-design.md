# Mode 3 — 스냅 기준 신원: 무작위 salt + 암호화 백업(salt 만), PPID·auid 에서 uid 를, C_attr 에서 blind 를 뺀다 (설계, 2026-11-13)

- 상태: **사용자 승인(2026-11-13)** — 방향은 사용자 승인(2026-11-13 대화, 같은 날 뒤 "무작위 salt 초안으로 가줘"). 승인된 항목: 무작위 루트 없이 **스냅 하나에 salt 하나**, 백업은 **스냅 설치 시점에 localhost:5100** 이 다룬다,
  **PPID 는 스냅별로 구분**(uid 를 뺀다), **IdP 에는 auid 대신 H(salt)** 를 준다, **같은 IdP 에서 한 스냅의 두 번째 계정은 거절**,
  IdP 는 **honest-but-curious**(IdP 공모는 범위 밖), salt 탈취는 위협 모델에서 뺀다. 같은 날 뒤 대화에서 더한 것: **백업에는 salt 만 넣는다**(R5 — "salt 만 백업하는 게 더 낫지 않아?"),
  그에 따라 C_attr 에서 blind 를 뺀다(R15). §9 의 세 건도 같은 날 확정했다.
- 용어: 이 문서의 **salt** 는 코드의 `s_u` 다(변수·필드 이름은 바꾸지 않는다 — 이름 변경은 이 스펙 밖).
- 선행 조건: 스냅 0.4.0(스펙 `2026-11-12-mode3-no-pk-u-design.md`, sk_u 제거)이 **먼저 끝나고 커밋된 뒤** 시작한다(끝났다 — `8f9d6e1` 까지 커밋, 미배포) — 같은 파일
  (`snap-mode3/src/{crypto,index}.js`, `tests/helpers/snap_sim.mjs`, `snap-mode3/test/rpc.test.mjs`)과 같은 회로(`pi_idp`)를 고친다.
- 대체: `2026-11-12-mode3-snap-derived-secrets-design.md` 의 S1·S2(시드 유도), `2026-11-12-mode3-snap-account-index-design.md` 전체(계정 번호 k),
  덱 3장·논문의 PPID 식 `H(uid, salt, rid, chain_id)`(D13). 같은 스펙의 S3(복구 = 같은 비밀로 다시 등록, IdP `restored` 경로)는 그대로 쓴다 — 비밀의 출처만 백업으로 바뀐다.
- 배경: 시드 유도(`snap_getEntropy`)는 salt 를 MetaMask SRP·스냅 ID 에 묶어 설계가 MetaMask 에 종속된 것처럼 보인다. 실제로 회로·컨트랙트·IdP·에이전트는 salt 값만 보고
  출처를 모른다. 그래서 규칙을 하나로 둔다 — **salt 는 무작위, 사용자는 암호화 백업(파일 + 백업 비밀번호)으로 지킨다.** 스냅은 이 규칙의 한 구현이고 MetaMask 는 편의다.
  또 RP 쪽 신원 단위를 IdP 계정(uid)이 아니라 **스냅(salt)** 으로 옮긴다 — IdP 계정을 잃거나 바꿔도 같은 스냅이면 같은 PPID 다.
- 비범위: C_u 식·tag 식(그대로 — uid·salt 를 계속 묶는다. C_u 의 `blind_u` 도 그대로 — IdP 가 자격증명과 함께 주는 값이고 C_attr 의 blind 와 무관하다), 파일 모드의 비밀 공급(그대로), 웹 모드(브라우저 사용자 페이지 — 2026-10-22 부터 개발 중지, §8 후속),
  Mode 1·Mode 2(`idp_state.json` 등 Mode 2 상태는 건드리지 않는다).

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| R1 | 스냅은 **salt 를 하나만** 갖는다 — 무작위로 한 번 만들고(또는 백업에서 불러오고) 그 뒤로는 그 값을 계속 쓴다. | 사용자 결정(무작위 루트·계정 번호 없음). |
| R2 | salt 는 **스냅 안에서** `crypto.getRandomValues` 로 만든다(범위 [1, 2^250−1], 지금 `SCALAR_MAX` 검사와 같다). `snap_getEntropy` 권한을 뺀다. | 페이지가 만들면 생성 시점의 비밀이 페이지에 먼저 생긴다. 스냅이 만들고 백업 때 한 번 내준다. 250비트라 우연한 충돌은 무시한다(사용자 2^40 명에서도 ≈ 2^−171). |
| R3 | **설치 직후 설정은 zk 스냅 화면(`localhost:5100/`, `mode3/wallet.html`)** 이 한다: "새로 만들기 / 백업에서 불러오기". | 스냅 설치(`wallet_requestSnaps`)를 이 화면이 하고, 스냅을 부를 수 있는 오리진은 :5100 뿐이다. 속성 도구(`/attr.html`)도 설치를 시작할 수 있으므로(attr.html:255) salt 가 없으면 zk 스냅 화면으로 보낸다. |
| R4 | 스냅은 **설치 때 자동으로 salt 를 만들지 않는다**(`onInstall` 없음). "새로 만들기" 가 부를 때 생긴다. | 재설치한 사용자가 모르는 사이 새 salt 로 가입하는 것을 막는다 — 불러오기를 먼저 고를 수 있어야 한다. |
| R5 | **백업에는 salt 만 넣는다** — 파일은 설치 직후 zk 스냅 화면이 **한 번** 만든다(봉인 형식은 D20 의 `lib/browser/attr_backup.js` 그대로, 평문은 `{ version: 4, s_u }`). 속성 도구는 백업을 만들지도 읽지도 않는다 — "암호화 백업 내려받기"·"백업 불러오기"·"3. 자동 백업(암호화)" 를 지운다(D20 의 자동 백업·파일 핸들·IndexedDB `zkd-attr-backup` 설정 폐기). | 사용자 결정(2026-11-13). 되찾을 수 없는 값은 salt 뿐이다 — 속성은 사용자가 아는 값이라 다시 넣고, 커밋먼트는 R15 로 다시 계산되며, uid 는 zkID 로그인에서 온다. 백업을 커밋먼트마다 다시 쓸 일이 없고 파일에 개인 속성이 없다. 대가: 복구 뒤 속성 도구에서 속성을 한 번 다시 넣는다. |
| R6 | **백업 강제는 스냅이 한다** — `backedUp` 이 참이 아니면 salt 를 밖으로 내거나 가입·로그인으로 이어지는 RPC 를 거절한다(§2.3). | 화면만 막으면 속성 도구·RP 팝업으로 우회된다. 백업 없이 PPID 지갑이 생기는 구간을 없앤다. |
| R7 | **백업 확인 = 저장한 파일을 다시 열어 같은 salt 가 나오는지** 화면이 확인한 뒤 `confirmBackup({ s_u })` 로 알린다. 스냅은 자기 값과 같을 때만 `backedUp = true`. | 스냅은 파일을 볼 수 없다. 복호화한 값을 대조하는 것이 저장이 실제로 됐다는 최소 증거다(호출 오리진은 :5100 뿐 — 지금 신뢰 모델과 같다). |
| R8 | **"스냅 초기화"(`reset`)는 salt·backedUp 을 남기고** 등록·동의 기록·userCred 만 지운다. salt 까지 지우는 것은 스냅 제거뿐이다. | 초기화 뒤 다시 가입하면 같은 auid·PPID. 비밀을 지우는 버튼이 백업 없는 손실로 이어지지 않게. |
| R9 | **PPID = Poseidon(salt, arid, chainid)** — uid 를 뺀다(`circuits/pi_cred.circom` ③, `lib/mode3_credential.js` `ppid`). | 사용자 결정: RP 쪽 신원 단위는 스냅. arid 로 RP 사이, chainid 로 체인 사이 연결 불가는 그대로. IdP 는 salt 가 없어 PPID 를 계산하지 못한다. auid(R10)와는 입력 개수가 달라(3 vs 2) Poseidon 인스턴스가 다르다. |
| R10 | **auid = Poseidon(T_AUID2, salt)** — uid 를 뺀다(`pi_idp` ②, `pi_cred` ②, `auidOf`). 도메인 상수는 새 값(ASCII `"MODE3AUID2"` 빅엔디언)으로 바꿔 옛 정의의 값과 섞이지 않게 한다. auid_s = Poseidon(T_AUIDS, auid, arid, r_rp)·등록부 리프 Poseidon(auid, Cf_u) 의 **식은 그대로**(auid 값만 바뀐다). | 사용자 결정(IdP 에는 H(salt)). salt 가 250비트라 IdP 가 auid 에서 salt 를 대입으로 찾지 못한다. PPID 는 auid 가 아니라 salt 에서 바로 만든다(메모 "PPID 는 auid 로 만들지 않음" 유지). |
| R11 | **같은 IdP 에서 한 스냅(같은 auid)의 계정은 하나** — 이미 다른 uid 에 묶인 auid 로 등록하면 IdP 가 `auid_taken`(409)으로 거절한다. 같은 uid·같은 auid 의 재등록은 지금처럼 `restored`. | 사용자 결정(거절). auid 가 IdP 의 계정 키로 그대로 남아 등록부·복구 경로·관리자 표를 다시 설계하지 않는다. 결과적으로 honest-but-curious IdP 가 자기 기록에서 "같은 스냅의 여러 계정" 을 볼 일도 없다. |
| R12 | **위협 모델**: IdP 는 honest-but-curious, IdP 끼리의 공모는 범위 밖(그래서 auid 에 IdP 식별자를 섞지 않는다 — 여러 IdP 가 같은 스냅에서 같은 auid 를 본다). salt 탈취(백업 파일 유출 + 비밀번호 대입, 단말 감염)는 범위 밖. | 사용자 결정(2026-11-13). 범위 밖 항목은 논문 위협 모델 절에 한계로 적는다(§6). |
| R13 | **계정 번호 k 를 없앤다** — `nextIndex`·`setNextIndex`·`index` 인자·응답의 `index`·속성 도구 "계정 번호" 칸·zk 스냅 화면 번호 표시·에이전트 기록의 `index`. | R1 로 계정마다 비밀을 나눌 필요가 없다. 옛 기록에 남은 `index` 는 읽을 때 무시한다. |
| R15 | **C_attr = Poseidon(T_ATTRC4, salt, attrs[0..5])** — blind 를 뺀다(도메인 ASCII `"MODE3ATTRC4"`, `lib/mode3_attr_commit.js` `attrCommit({ s_u, attrs })`, 속성 도구 기록 version 4 — `blind`·`index` 없음). | R5 의 짝(사용자 결정, §9-3): blind 가 무작위면 salt 만으로 같은 커밋먼트를 다시 만들 수 없어, 복구할 때마다 프로필을 바꿔야 한다(그러면 IdP 가 세션을 폐기한다, D19). salt 가 이미 식 안의 250비트 비밀이라 숨김은 그대로다(IdP 는 salt 없이 속성을 대입해 볼 수 없다). 대가: 같은 salt·같은 속성이면 항상 같은 값 — 속성을 A → B → A 로 바꾸면 IdP 가 "예전 값으로 돌아갔다" 는 것을 알고, 같은 스냅을 쓰는 두 IdP 는 같은 C_attr 를 본다(IdP 공모는 R12 로 범위 밖 — auid 도 이미 같다). C_attr 는 회로·컨트랙트에 쓰이지 않아 zkey 와 무관하다. |
| R16 | **파일 선택 직후의 헛클릭을 무시한다** — 파일 선택 창이 닫히고 `change` 가 온 뒤 0.7초 동안 불러오기 영역의 버튼(불러오기·취소 등) 클릭을 받지 않는다. | 사용자 보고(2026-11-13): 파일 선택 창에서 파일을 **더블클릭**하면 두 번째 클릭이 창이 닫힌 뒤 페이지로 떨어져, 막 나타난 비밀번호 칸의 "취소" 를 눌러 버린다 — 아무 일도 없던 것처럼 보였다(추정 경로 — 자동화로는 OS 파일 창을 재현하지 못해 사용자 확인으로 검증한다). |
| R14 | **이전 없음 — 데모 리셋.** R9·R10 으로 모든 PPID·auid·지갑 주소가 바뀌므로 0.4.x 스냅 상태·IdP 상태를 이행하지 않는다. 스냅 0.5.0 은 옛 상태를 만나면 등록·동의 기록을 버리고 "salt 없음"(설정 화면)으로 시작한다. IdP 상태는 버전을 올리고(13 → 14) 옛 버전은 기동을 거부한다(지금 이행 규칙과 같은 방식). | 옛 salt 를 살려도 PPID 가 바뀌어 RP 계정이 이어지지 않는다 — 이행의 이득이 없다. 리셋은 기존 스크립트(`scripts/demo_snap_reset.sh` 등, 상태 파일을 백업해 두고 새로 시작)로 한다. |

## 2. 스냅 (`snap-mode3`, 0.4.0 → 0.5.0)

### 2.1 권한·버전
- `snap.manifest.json` `initialPermissions` 에서 `snap_getEntropy` 를 뺀다. 버전 0.5.0(`package.json` 도). `shasum` 은 빌드가 다시 쓴다.

### 2.2 상태
- 최상위에 `salt: { s_u, createdAt, source: 'new' | 'import', backedUp, backedUpAt } | null`. `registration.s_u` 는 **두지 않는다**(등록은 `salt.s_u` 를 쓴다 —
  값이 두 군데 있어 어긋나지 않게).
- `getState()`: 0.4.x 모양(최상위 `salt` 없음)이면 R14 대로 등록·동의 기록·userCred·nextIndex 를 버리고 `salt: null` 로 시작한다. 다음 저장 때 저장소에서도 사라진다.
- `src/crypto.js`: `ENTROPY_SALT_S_U`·`saltFromEntropy`·`deriveRegistrationSecrets`·`isIndex`·`INDEX_MAX` 를 지우고 `randomSalt()`(R2)를 둔다.

### 2.3 RPC

| RPC | 동작 | backedUp 필요 |
|---|---|---|
| `initSalt({})` (새) | salt 가 없을 때만 무작위로 만들고 `{ s_u }` 를 돌려준다(백업 파일을 만들 화면에 한 번). 이미 있으면 `salt_exists`. | 아니오 |
| `importSalt({ s_u })` (새) | 백업에서 꺼낸 값을 넣는다. 형식·범위 검사. salt 가 없거나 **등록이 없고 backedUp 이 거짓**일 때만 — 그 밖에는 `salt_exists`. 확인 창(snap_dialog). 넣은 값은 `backedUp = true`. | 아니오 |
| `confirmBackup({ s_u })` (새) | R7. 같으면 `backedUp = true`·`backedUpAt`. 다르면 `backup_mismatch`. | 아니오 |
| `exportSaltForBackup({})` (새) | 백업 다시 만들기(새 파일·새 비밀번호)용 `{ s_u }`. salt 없으면 `no_salt`. | 아니오 |
| `getSalt({})` | `{ s_u }`(속성 도구 C_attr 계산용 — 속성 도구가 "커밋먼트 만들기" 때 부른다). `index` 인자·응답 필드 삭제. | **예** |
| `prepareRegister({})` · `register({ uid, s_u? })` | 비밀은 `salt.s_u`. `register` 에 `s_u` 가 오면 같을 때만(다르면 `salt_mismatch` — `salt_not_derived` 대체). | **예** |
| `consentLogin` · `consentDisclosure` | 증인의 salt 는 `salt.s_u`. | **예** |
| `getPublicInfo` | `hasSalt`·`backedUp` 을 더하고 `index`·`nextIndex` 를 뺀다. 비밀 없음. | 아니오 |
| `getStoredState` | `salt` 를 싣는다("내 계정" 탭, 비밀은 화면이 기본 가림). `nextIndex` 삭제. | 아니오 |
| `showSalt` | `salt.s_u`. | 아니오 |
| `reset` | R8. 확인 창 문구 "등록·동의 기록을 지웁니다. salt 는 남습니다". | 아니오 |
| `setNextIndex` | **삭제**. | — |

- 거절 사유: `no_salt`(설정 전), `backup_required`(backedUp 거짓), `salt_exists`, `salt_mismatch`, `backup_mismatch`. 화면은 앞의 둘이면 설정 화면으로 보낸다.

## 3. 회로·라이브러리·컨트랙트

### 3.1 회로 (zkey 재생성 필요 — 이 스펙 승인이 `pi_idp`·`pi_cred` 의 재빌드 승인을 포함하지 않는다. 구현 계획 단계에서 따로 승인받는다)
- `circuits/pi_idp.circom` ②: `auid === Poseidon(T_AUID2, s_u)`. 공개 입력의 개수·순서는 그대로(`[0] uid` 는 남는다 — C_u 와 IdP 계정을 묶는다).
- `circuits/pi_cred.circom` ②: auid 를 같은 식으로. ③: `PPID === Poseidon(s_u, arid, chainid)`(Poseidon(3)). 공개 입력의 개수·순서는 그대로(34개, `[0] PPID`).
- 머리 주석의 식(②·③)과 `circuits/lib/mode3_commit.circom` 의 uid 설명("PPID 유도에 쓰인다")을 고친다.
- 빌드: `scripts/build_mode3_circuit.sh`(회로 이름을 받는다). 기존 ptau 를 쓴다 — ptau 재생성은 하지 않는다.

### 3.2 라이브러리
- `lib/mode3_credential.js`: `DOMAIN_MODE3_AUID` → 새 상수(R10), `auidOf({ s_u })`(uid 인자 삭제), `ppid({ s_u, arid, chainid })`(uid 인자 삭제). 호출하는 곳
  (`mode3/user/core/user_core.js:262` 등, `lib/mode3_secret_source.js` `validateWitness` 의 auid 대조, 에이전트·IdP·테스트)을 모두 맞춘다.
- `tests/test_mode3_artifacts.mjs` 의 `.sym` 대조와 JS↔회로 일치 테스트가 새 식을 본다.

### 3.3 컨트랙트·배포
- `Mode3Wallet.sol`·`Mode3WalletFactory.sol` 의 코드는 그대로(PPID 는 공개 입력 [0] 의 값으로만 쓴다). `pi_cred` 검증자 컨트랙트를 새 zkey 로 다시 만들고
  검증자·팩토리를 다시 배포한다(데모 리셋 스크립트가 하는 경로).

## 4. IdP (`cia.js`, `lib/mode3_cia_state.js`)
- 등록(일반·Google 래퍼 경로 모두): 요청의 auid 가 **다른 uid** 의 계정에 이미 있으면 `409 auid_taken`(R11). 같은 uid 면 지금처럼 `restored`. 검사 순서는 π_IdP 검증 뒤
  (증명이 틀린 요청에 auid 존재 여부를 알려 주지 않는다).
- 상태 버전 13 → 14(R14): 14 는 auid 의 뜻이 바뀌었다는 표시다. 13 이하는 기동을 거부하고 리셋을 안내한다. **Mode 2 의 `idp_state.json` 과는 무관하다**(지우지 않는다).
- 관리자 페이지 "uid ↔ auid 대응" 표: 열 이름·설명을 "uid ↔ auid(스냅 가명)" 로. 계정 하나에 auid 하나라 표 구조는 그대로.
- auid_s 를 이용한 조건부 추적(RP·IdP 협력)은 식이 그대로라 동작한다 — 결과가 가리키는 것이 계정이자 스냅이다(R11 로 둘이 일대일).

## 5. 화면 (:5100)

### 5.1 zk 스냅 화면(`mode3/wallet.html`)
- 연결(설치) 뒤 `getPublicInfo` 의 `hasSalt`·`backedUp`:
  - `hasSalt` 거짓 → **설정 카드**: "새로 만들기" / "백업에서 불러오기". 다른 탭·서비스 로그인 흐름보다 먼저.
  - `hasSalt` 참·`backedUp` 거짓 → "백업을 만들어야 계속할 수 있습니다" 카드(새로 만들기의 ②~④).
- 새로 만들기: ① `initSalt` ② 백업 비밀번호 두 번 + 파일 고르기(`showSaveFilePicker`, `lib/browser/attr_backup.js` 의 `backupKey`·`sealBackup` — 키·파일 핸들은 **저장해 두지 않는다**, R5)
  ③ 기록 `{ version: 4, s_u }` 를 봉인해 쓴다 ④ 파일을 다시 읽어 `openBackup` → 같은 값인지 → `confirmBackup`. `showSaveFilePicker` 가 없는 브라우저는 안내 문구로 멈춘다(지금 자동 백업과 같은 제약 — Chrome·Edge).
- 백업 다시 만들기(설정 뒤, "내 계정" 탭): `exportSaltForBackup` → ②~④ 와 같은 절차로 새 파일·새 비밀번호.
- 불러오기: 파일 + 비밀번호 → `openBackup` → `importSalt`. 기록에서 **`s_u` 만** 꺼낸다 — 옛 백업(속성 도구 version 2·3, 속성·blind 가 든 기록)도 `s_u` 가 있으면 받고 나머지는 무시한다.
  속성 도구 기록(localStorage)은 채우지 않는다(R5). 결과·오류는 버튼 바로 아래에 보이고, 파일 선택 직후의 클릭은 R16 대로 무시한다.
- 복구 뒤 속성: 속성 도구에서 같은 속성을 다시 넣으면 같은 C_attr 가 나온다(R15) — zkID 프로필을 다시 붙여 넣을 필요가 없다.
- RP 로그인 팝업이 `no_salt`·`backup_required` 를 받으면 설정 카드로 안내하고 로그인은 실패로 끝낸다(팝업 안에서 백업 흐름을 돌리지 않는다).
- IdP 가 `auid_taken` 을 주면 "이 스냅은 이 IdP 에 이미 다른 계정으로 등록돼 있습니다" 를 보인다.
- 지울 것: 계정 번호 표시·다음 가입 번호, `getSalt` 의 index 처리와 0.1.0/0.2.0 판별 분기(wallet.html:648-671), 복구 흐름의 `index: rec.index`(754).

### 5.2 속성 도구(`mode3/attr.html`)
- 입력은 지금처럼 속성뿐이다(2026-11-13 `8f9d6e1` — uid 는 zkID 로그인에서, salt 는 "커밋먼트 만들기" 때 `getSalt`). `getSalt` 가 `no_salt`·`backup_required` 면 zk 스냅 화면으로 가라는 문구.
- R15: `attrCommit({ s_u, attrs })`. 기록 version 4 = `{ version: 4, schema, uid, s_u, profile, attrs, commit, createdAt }`(`blind`·`index` 없음). 저장된 version 1~3 기록은 "다시 만드세요".
  "커밋먼트 재료" 표에서 blind 줄을, 안내 문구에서 "만들 때마다 새 blind 를 뽑습니다" 를 지운다. 배지 문구는 "속성·salt 는 서버로 보내지 않음".
- R5: "암호화 백업 내려받기"·"백업 불러오기"(비밀번호 칸 포함)·"3. 자동 백업(암호화)" 절과 그 코드(IndexedDB `zkd-attr-backup`, 파일 핸들, `writeAutoBackup`)·문자열을 지운다. "지우기" 는 남는다.
- 스냅 창(`wallet.html` `readAttrRecord`)은 version 4 기록만 받는다.

### 5.3 백업 파일 형식
- 봉인 형식(`zkd-attr-backup` v1, kdf·box)과 `lib/browser/attr_backup.js` 는 그대로 쓴다(형식 이름은 바꾸지 않는다 — 옛 파일을 계속 열 수 있게). `BACKUP_MIN_PASSWORD` 는 8자 그대로(§9-1).
- 평문은 `{ version: 4, s_u }` — 다른 필드를 쓰지 않는다. 쓰기 직전에 `s_u` 의 형식·범위를 검사하고, 없으면 봉인하지 않는다.
- 읽을 때는 version 과 무관하게 **유효한 `s_u`(10진, [1, 2^250−1])가 있으면 받는다**. 없으면 `bad_backup`.
- 속성 도구 기록(localStorage `mode3_attr_tool_v1`)은 백업과 별개다(§5.2 — 이 브라우저에만 남고, 잃으면 다시 만든다).

## 6. 동작 변화·보안 메모
- **한 스냅 = RP 에서 한 신원**: IdP 계정을 잃어도 같은 스냅(또는 백업)으로 새 계정을 만들면 RP 마다 같은 PPID 로 이어진다. 여러 IdP 를 같은 스냅으로 쓰면 RP 에서 같은 PPID 다.
- **IdP 계정 폐기와 RP 신원**: 계정을 폐기해도 같은 스냅으로 다른 IdP 의 계정을 쓰면 같은 PPID 로 로그인된다(같은 IdP 에서는 R11 로 새 계정을 못 만든다). RP 가 PPID 를 막으면 그 스냅의 모든 계정이 막힌다.
- **11-10 결정(rp-social-logins, 계정 연결은 RP)과의 관계**: 같은 스냅이면 RP 가 연결하지 않아도 같은 PPID 다. RP 연결 기능은 서로 다른 스냅(서로 다른 salt)을 묶는 용도로 남는다 — 설명만 고친다.
- **손실**: 백업 파일 또는 비밀번호를 잃고 스냅 상태도 잃으면 salt 를 되찾을 수 없다 — PPID 지갑 자산이 잠기고 RP 계정이 끊긴다. 위협 모델에 사용자 책임으로 적고,
  R6 이 백업 없이 자산이 생기는 구간을 막는다. 문서는 파일을 PC 밖에 두라고 안내한다.
- **백업 파일에 든 것**: salt 하나. 속성·uid·커밋먼트는 없다. 파일 + 비밀번호가 새면 salt 가 새고(R12 범위 밖), 그때는 C_attr 의 속성도 대입으로 찾을 수 있다(R15 — blind 가 없다).
- **범위 밖(R12)**: salt 탈취 — uid 가 PPID 에서 빠져 salt 만으로 자기 IdP 계정을 만들어 같은 PPID 를 증명할 수 있다(같은 IdP 는 R11 이 막지만 피해자가 먼저 등록한 경우뿐).
  IdP 공모 — 같은 스냅은 모든 IdP 에 같은 auid 를 낸다. 둘 다 논문에 한계로 적는다.

## 7. 문서
- `docs/MODE3_DEMO.md`: 스냅 0.5.0(권한 변경으로 재승인), 설치 직후 백업 절차(백업에는 salt 만), 속성 도구에서 백업 기능 삭제·C_attr 식(R15), D20 메모에 대체 표시, 복구 시연(스냅 삭제 → 재설치 → 백업에서 불러오기 → RP 로그인 → 같은 PPID),
  "백업 파일·비밀번호를 잃으면 복구할 수 없다", 데모 리셋 필요(R14), 계정 번호 절 삭제, `auid_taken`.
- 대체된 스펙 두 개의 머리에 "2026-11-13 대체: 2026-11-13-mode3-snap-random-salt-backup-design.md" 를 단다(본문은 남긴다).
- 논문·덱의 식 수정(PPID = H(salt, rid, chain_id), auid = H(salt))은 이 스펙 밖에서 따로 한다 — 구현과 같은 시점에 할지 사용자가 정한다.

## 8. 후속(이 스펙 밖)
- 웹 모드의 복구 코드(`zkd1.` 시드 → `SHA-256(seed ‖ "zkd3/s_u")`, `lib/mode3_wallet.js:42`)를 같은 규칙(무작위 salt + 같은 백업 형식)으로 바꾸는 일 — 웹 모드 재개 때.
- 백업 KDF 를 메모리 하드 함수(Argon2id 등)로 바꾸는 일.
- PPID 재측정: 회로가 바뀌므로 `results/` 의 ZKP 벤치마크(10회)를 다시 돌릴지(메모 "PPID follow-up: re-benchmark").

## 9. 확정(사용자 2026-11-13)
1. 백업 비밀번호 하한: **8자 그대로**(12자 추천은 받지 않았다).
2. 논문·덱 식 수정: **구현 뒤 따로** — 이 스펙·구현 계획에 넣지 않는다.
3. C_attr 에서 blind 를 **뺀다**(R15).

## 10. 테스트
- 스냅 단위(`snap-mode3/test/rpc.test.mjs`, `bash scripts/run_tests.sh snap`): initSalt 한 번만(두 번째 `salt_exists`)·범위; backedUp 전에는 getSalt·prepareRegister·register·
  consentLogin·consentDisclosure 가 `backup_required`, salt 없으면 `no_salt`; confirmBackup 일치/불일치; importSalt 허용·거절 조건과 확인 창; reset 뒤 salt·backedUp 유지;
  0.4.x 상태를 만나면 등록·동의 기록을 버리고 salt 없음; 응답·상태 어디에도 index·nextIndex 없음; `snap_getEntropy` 를 부르지 않는다.
- 속성 도구: 백업 버튼·자동 백업 절이 없다; 기록 version 4 에 blind·index 가 없다; 같은 salt·같은 속성이면 같은 커밋먼트, 속성이 다르면 다르다; version 3 기록은 "다시 만드세요"; `getSalt` 가 `backup_required` 면 안내 문구.
- 라이브러리(`tests/test_mode3_attr_commit.mjs`): `attrCommit({ s_u, attrs })` — blind 인자를 받지 않고, 도메인이 `MODE3ATTRC4` 라 옛 식의 값과 다르다.
- 시뮬레이터(`tests/helpers/snap_sim.mjs`)를 같은 동작으로 맞추고 `derivedSecrets` 를 없앤다.
- 라이브러리·회로(`npm test`): `auidOf`·`ppid` 의 새 식과 회로 일치(.sym 대조 포함); 같은 salt·다른 uid 면 같은 auid·같은 PPID; 다른 salt 면 다르다.
- IdP(`bash scripts/run_tests.sh chain`): 같은 auid·다른 uid 등록은 `auid_taken`, 같은 uid 는 `restored`; 증명이 틀린 요청은 auid 존재와 무관하게 `bad_idp_proof`; 상태 13 은 기동 거부.
- 컨트랙트(`bash scripts/run_tests.sh contract`): 새 `pi_cred` 로 만든 π 가 지갑에서 통과(`test/Mode3Wallet.test.mjs`).
- 브라우저(`bash scripts/run_tests.sh browser`): 설치 → 설정 카드 → 새로 만들기(파일 저장·재열기·confirmBackup) → RP 로그인 성공; 백업 전 RP 로그인은 안내 문구로 실패;
  스냅 상태 삭제 → 불러오기 → 같은 PPID, 속성 도구에서 같은 속성 → 같은 C_attr; 옛 형식(속성이 든) 백업도 salt 만 받는다; 파일 `change` 직후 0.7초 안의 "취소" 클릭은 무시되고 그 뒤 클릭은 듣는다(R16); 같은 스냅으로 두 번째 계정 등록 → `auid_taken` 문구.
- `tests/test_attr_backup.mjs`: 기록은 `{ version: 4, s_u }`(비밀번호 하한 8자는 그대로).
