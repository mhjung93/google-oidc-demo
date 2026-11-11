# Mode 3 — 스냅 시드 유도 비밀: s_u·sk_u 를 snap_getEntropy 에서, 복구 = 같은 비밀로 다시 등록 (설계, 2026-11-12)

- 상태: 사용자 승인(2026-11-12, 대화 중 "안 A" 선택 → 범위 "s_u·sk_u 둘 다 + 복구 흐름" → 설계안 "ㅇㅋ").
- 배경: 스냅 모드의 s_u 는 무작위라 MetaMask 저장소(스냅 상태)와 속성 도구 기록을 둘 다 잃으면 되찾을 수 없다 — 같은 PPID 도, RP 계정도 끊긴다.
  속성 도구 자동 암호화 백업(D20, 26bf1f8)은 그 위험을 줄이지만 사용자가 파일·비밀번호를 지켜야 한다. 사용자가 고른 대안 비교
  ("스냅 기준 PPID" A·B·C) 중 **안 A — PPID 식은 그대로 두고 비밀만 시드에서 유도** 를 택했다. 안 B(uid 를 뺀 PPID)는 유출된 k 로 자기 계정에 등록해
  같은 PPID 를 만드는 탈취를 막으려면 zkID 쪽 계정 연결이 다시 필요해 11-10 결정(연결은 RP)과 부딪치고, 회로 재빌드가 든다.
- 비범위: PPID 식·회로·컨트랙트(바꾸지 않는다, zk 재빌드 없음), 파일 모드·웹 모드(그대로), 이미 등록된 스냅의 이전(저장된 무작위 비밀을 계속 쓴다),
  다중 IdP, 속성(attrs·blind)의 시드 유도(속성 도구 기록·백업 몫으로 둔다).

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| S1 | 스냅이 **s_u 와 sk_u 를 `snap_getEntropy` 에서 유도**한다. 같은 SRP·같은 스냅 ID 면 언제나 같은 값. | 사용자 선택(범위 "둘 다"). 시드만 있으면 salt 와 서명키를 둘 다 되찾는다. 대가: 스냅 ID 가 바뀌면 값도 바뀐다(§2.3). |
| S2 | 속성 도구의 salt 는 **스냅에서 가져온다** — 직접 입력 칸을 없앤다(11-10 의 "사용자가 salt 를 미리 정한다" 를 대체). | 사용자 무선호 → 추천안. 직접 넣은 salt 로 등록하면 시드 복구가 안 되는 계정이 섞인다. |
| S3 | **복구 = 같은 비밀로 다시 등록.** IdP·에이전트는 이미 등록된 계정이라도 (auid, pk_u) 가 저장값과 같고 등록 서명이 맞으면 409 대신 기존 등록을 돌려준다(`restored:true`). | 별도 "복구" 흐름 없이 평소 등록 경로가 그대로 복구가 된다 — 스냅만 비었을 때(에이전트 상태 있음)와 새 PC(둘 다 없음)를 한 흐름으로. 로그인 수단(비밀번호·Google)과 시드가 **둘 다** 있어야 하므로 공격면은 지금과 같다. |
| S4 | 이미 등록된 스냅은 **그대로** — 저장된 무작위 s_u·sk_u 를 계속 쓴다. 시드 복구를 쓰려면 데모 리셋 뒤 새로 등록한다. | 이전(migration)은 PPID 가 바뀌어 RP 계정이 끊기므로 하지 않는다. |

## 2. 스냅 (`snap-mode3`)

### 2.1 권한·버전
- `snap.manifest.json` `initialPermissions` 에 `"snap_getEntropy": {}` 를 더하고 버전을 `0.1.0 → 0.2.0` 으로 올린다.
- 설치된 스냅은 지갑 페이지의 연결(`wallet_requestSnaps`)에서 새 권한 승인과 함께 갱신된다. **갱신 때 Flask 가 기존 스냅 상태를 유지하는지는 구현 단계에서 실제로 확인한다**(확인 전 미검증 — 유지되지 않으면 S4 의 "이미 등록된 스냅" 이 비게 되므로 런북에 적는다).

### 2.2 유도 (`src/crypto.js`)
- `deriveRegistrationSecrets()` 가 `createRegistrationSecrets()`(무작위)를 대체한다:
  - `e1 = snap.request({ method: 'snap_getEntropy', params: { version: 1, salt: 'zkd/mode3/s_u/v1' } })` → `s_u = 1 + (BigInt(e1) mod (2^250 − 1))` — 범위 [1, 2^250−1] 로 지금 `SCALAR_MAX` 검사와 같다.
  - `e2 = snap.request({ method: 'snap_getEntropy', params: { version: 1, salt: 'zkd/mode3/sk_u/v1' } })` → `sk_u = e2` 의 32바이트 hex(64자, `0x` 없음) — 지금 형식과 같다(EdDSA-Poseidon 은 아무 32바이트나 받는다).
- 두 salt 문자열의 `v1` 은 유도 규칙의 버전이다. 규칙을 바꾸면 `v2` 로 — 같은 문자열에 다른 규칙을 얹지 않는다.

### 2.3 RPC
- `register`·`prepareRegister`: 비밀을 유도값으로 만든다. `register` 의 `params.s_u` 는 **유도값과 같을 때만** 받는다 — 다르면 `salt_not_derived` 로 거절(속성 도구 옛 기록의 직접 입력 salt 가 섞이지 않게).
- **새 `getSalt`**: 등록 전에도 유도한 `s_u` 를 돌려준다(속성 도구용). 등록 여부와 무관하게 같은 값. 확인 창 없음(지금 `register` 가 s_u 를 돌려주는 것과 같은 노출 — 부를 수 있는 오리진은 여전히 지갑 오리진 `:5100` 뿐).
- `showSalt`·`getPublicInfo`·`reset` 은 그대로. `reset` 뒤에도 유도값은 같다(시드가 같으므로).
- 문서화할 한계: **스냅 ID 가 바뀌면 엔트로피가 바뀐다** — 지금 `local:http://localhost:8082` 에서 포트를 바꾸거나 npm 배포판으로 옮기면 모든 유도값이 달라진다.

## 3. 속성 도구 (`mode3/attr.html`)
- salt 칸은 읽기 전용, 옆에 **"스냅에서 가져오기"** 버튼. 누르면 `/wallet/config` 의 `snapId` 로 `wallet_requestSnaps` → `wallet_invokeSnap(getSalt)` → 칸을 채운다.
  MetaMask 가 없거나 거절하면 사유를 판정 칸에 보인다(기존 Demo.reason 방식).
- uid·속성 입력과 C_attr·auid 계산, 저장·자동 백업(D20)은 그대로.
- 옛 기록(직접 넣은 salt)도 열린다. 열 때(또는 "스냅에서 가져오기" 뒤) 기록의 s_u 가 스냅 salt 와 다르면 **"시드로 복구할 수 없는 salt"** 경고를 보인다(막지는 않는다 — 보기·내보내기는 계속).

## 4. 복구 = 같은 비밀로 다시 등록

### 4.1 IdP (`cia.js`)
- `registerAccount`: `state.accounts[uid].pk_u` 가 있을 때, 요청의 `auid` 가 `acct.auid` 와 같고 `pk_u` 가 `acct.pk_u` 와 같으며 `sig_reg` 가 그 `pk_u` 로 검증되면 → 슬롯을 새로 잡지 않고 `{ slot: acct.slot, restored: true }` — 상태는 201(새 등록과 같다, 에이전트·헬퍼가 201 만 성공으로 본다. 계획 Ruling P1). 하나라도 다르면 지금처럼 409.
  `beforeCommit`(1회용 코드 소비)는 복구에도 똑같이 적용한다. 상태 변경·게시는 없다. 계정이 `disabled` 면 복구도 409(`account_disabled`) — 폐기된 계정을 되살리지 않는다.
- `/cia/auth/code` 의 `purpose:'register'`: 이미 등록된 계정이라도 요청의 `auid` 가 `a.auid` 와 같으면 등록 코드를 낸다(복구). 다르면 지금처럼 409.
- `/cia/register` 의 Google(`id_token`) 경로와 `/cia/issue` 의 암묵 등록도 `registerAccount` 를 쓰므로 같은 규칙을 따른다.
- `/cia/user/register_code`(IdP `/user` 페이지 경로, auid 를 받지 않는다)는 지금처럼 409.
- 응답 `/cia/register` 201 에 `restored` 를 더한다(새 등록은 생략 또는 false). 테스트의 응답 키 목록 갱신 포함.

### 4.2 에이전트 (`mode3_wallet_agent.js` `/wallet/register`)
- 에이전트에 등록이 이미 있을 때: 이미 있는 `POST /wallet/register/resume`(s_u·sk_u → auid·pk_u 대조 → 기존 등록 반환, 다르면 409 `secrets_mismatch`)으로 처리한다. `/wallet/register` 는 바꾸지 않는다(계획 Ruling P2).
- 에이전트에 등록이 없을 때: 지금처럼 IdP 에 등록하고, IdP 가 `restored:true` 를 주면 그 slot 으로 저장한다.

### 4.3 스냅 팝업 (`mode3/wallet.html`)
- 지금 "에이전트에는 등록이 있지만 스냅은 비었다"(`already_registered` / `snap_empty`) 로 끝나는 분기는 **평소 등록 흐름으로 진행**한다 — 유도값이 같으므로 에이전트가 기존 등록을 돌려주고, 스냅이 `storeRegistration` 으로 채운다.
  유도값이 다르면(옛 무작위 등록, 다른 SRP) 에이전트가 409 `secrets_mismatch` 를 주고 팝업은 `snap_restore_mismatch`("이 스냅의 비밀이 등록과 다릅니다")로 멈춘다.
  스냅이 보류 등록(반쯤 된 Google 등록)인 경우도 같은 복구로 마저 채운다 — 예전의 "등록이 반만 됐다" 안내는 resume 이 실패할 때만 남는다.
- 복구 뒤 스냅에는 동의(consents)·사용자 자격증명(userCred)이 없다 — 다음 로그인에서 동의를 다시 받고 새 C_u 를 발급받는다(기존 흐름).
- 속성(attrs·blind)은 속성 도구 기록(또는 D20 백업에서 불러온 기록)에서 — 첫 등록과 같은 경로(f00c4c0). 기록이 없으면 속성 도구에서 다시 만든다:
  salt 는 스냅에서 같은 값이 오므로 auid 가 같고, 새 blind 로 C_attr 가 바뀌면 zkID 내 정보 저장 때 D19 흐름(기존 세션 폐기·새 C_u)이 돈다.

### 4.4 결과
- 같은 SRP 로 MetaMask 를 다시 설치(또는 스냅 상태를 잃음) → RP 에서 로그인 → 같은 uid·같은 s_u → **같은 PPID**, RP 계정이 그대로 이어진다.
- 데모 리셋(IdP·RP 상태를 비움) 뒤 같은 스냅·같은 uid 로 등록하면 이제 auid·PPID 가 리셋 전과 같다(전에는 새 무작위 값). 데모 리셋은 RP 계정도 비우므로 화면상 차이는 없다.
- 범위 밖(계획 Ruling P3): 스냅 등록은 남고 에이전트 상태만 잃은 경우 — 지금처럼 `already_registered`.

## 5. 테스트

- **스냅 RPC**(`snap-mode3/test/rpc.test.mjs`, `snap` 그룹): `snap_getEntropy` 스텁(시드 문자열 + salt 로 결정적 32바이트) —
  같은 시드면 `register`·`prepareRegister`·`getSalt` 가 같은 s_u·sk_u, 다른 시드면 다르다; `reset` 뒤에도 같다; 유도값과 다른 `params.s_u` 는 `salt_not_derived`; s_u 범위 [1, 2^250).
- **IdP**(`tests/test_cia_accounts.mjs` 또는 `test_cia_register_issue.mjs`, `chain` 그룹): 같은 (auid, pk_u, 서명)으로 재등록 → 200 `restored:true`·같은 slot·`registry.next` 그대로; auid 다름·pk_u 다름·서명 틀림 → 409/400; disabled 계정 → 409;
  `/cia/auth/code` register 목적 — 같은 auid 면 코드, 다르면 409.
- **에이전트**: 같은 비밀로 `/wallet/register` 재호출 → 200 restored, 다른 비밀 → 409.
- **브라우저**(`tests/test_mode3_browser.mjs`·`test_mode3_wallet_snap_oidc_browser.mjs`, `browser` 그룹; 페이지에 주입하는 `snap` 스텁에 `snap_getEntropy` 추가):
  등록 → RP 로그인(PPID P) → 스냅 상태 삭제 → RP 로그인 → 복구 등록 → 같은 PPID P·같은 RP 계정; 에이전트 상태까지 지운 경우도 같은 결과(IdP restored 경로);
  Google 계정도 같은 시나리오; 속성 도구 "스냅에서 가져오기" 가 스냅 salt 를 채우고 다른 salt 기록에는 경고.
- 새 케이스는 고치기 전 코드에서 실패하는 것을 먼저 확인한다.

## 6. 문서
- `docs/MODE3_DEMO.md`: 스냅 갱신(0.2.0, 새 권한 승인), 시드 복구 시연 절차(MetaMask 재설치 → 같은 SRP 로 복원 → RP 로그인 → 같은 PPID), 스냅 ID 가 바뀌면 값이 바뀐다는 한계.
- 속성 커밋먼트 스펙(`2026-11-06-…`) 결정 표에 "salt 는 스냅에서(11-10 직접 입력 대체)" 행.
