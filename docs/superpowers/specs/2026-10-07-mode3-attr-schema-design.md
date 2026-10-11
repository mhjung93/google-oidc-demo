# Mode 3 속성 매핑 계층 설계 — 공개 스키마와 타입별 인코딩 (V9 "스펙 2")

작성 2026-10-07. 상태: **확정(2026-10-07) — 구현 계획으로 진행**. 근거가 된 논의: 2026-10-07 대화(결정 D1~D5), V9 스펙 `2026-10-01-mode3-v9-registry-design.md` §5.4·§13(이 계층을 "스펙 2"로 예약), 현행 코드 `lib/mode3_credential.js`(`ATTR_SLOTS = 6`, `ATTR_MAX = 2^64`), `cia.js`, `mode3_wallet_agent.js`, `mode3_rp.js`, `contracts/AttrGate.sol`, `circuits/pi_cred.circom`.

## 0. 한 줄 요약

사용자 속성을 **사람이 읽는 값**(출생연도 `"1990"`, 국가 `"KR"`, 문자열)으로 다루고, **공개 스키마**가 정한 타입별 규칙(int 그대로, enum 은 스키마의 코드, string 은 64비트 해시)으로 인코딩해 C_u 의 슬롯에 넣는다. 회로·서명·Snap·지갑 상태가 쓰는 내부 표현("인코딩된 10진 문자열 6개")은 바꾸지 않고, 스키마와 인코더를 그 앞에 얹는다.

## 1. 왜

- 지금은 속성이 "10진 정수 6개"로만 다뤄진다. 슬롯 의미(0 = 출생연도, 1 = ISO 3166 숫자 국가코드, 2 = 등급)가 RP·AttrGate·화면·테스트에 흩어져 하드코딩돼 있고, 관리자 화면·지갑 화면·RP 정책이 모두 숫자(410, 392)를 그대로 보여 준다.
- V9 스펙 §5.4 가 이 경계를 이미 정해 두었다: "CIA·지갑·RP 의 `attrs` 인터페이스는 10진 문자열 6개로 두고, 스펙 2 가 그 앞에 스키마·인코더를 얹는다. 범위 술어는 순서가 있는 인코딩에만 의미가 있으므로 스키마가 슬롯마다 허용 술어를 표시한다." 이 문서가 그 스펙 2 다.
- 미팅 덱(2026-10-07)의 속성 장을 "uid·salt 포함 6개, 국가 = enum, 나머지 = 문자열"로 정리하면서 구현도 같은 그림을 갖게 한다.

## 2. 결정 (2026-10-07 사용자 확정)

| # | 결정 | 내용 |
|---|---|---|
| D1 | 스키마로 자유 정의 | 슬롯마다 이름·표시 이름·타입을 공개 스키마(JSON)로 정하고, 코드는 스키마만 읽는다. 기본 스키마는 §3.2. |
| D2 | enum 은 스키마에 코드 명시 | 항목마다 숫자 코드를 적는다. 국가는 ISO 3166-1 숫자 코드(KR = 410) — 현행 데이터·RP 정책 값이 그대로 유효하고, 목록 순서를 바꿔도 값이 변하지 않는다. |
| D3 | uid·salt 포함 6개(논리), 회로 유지 | 설명·덱에서는 C_u 가 uid, salt, 속성 4개 = 6개 값을 커밋한다. 구현 회로는 그대로(`attrs[6]`)이고 스키마가 쓰지 않는 슬롯 2개는 항상 0 이다. zkey·검증 컨트랙트·팩토리 기준 빌드를 다시 만들지 않는다. |
| D4 | 등급(grade) 제거 | 기본 스키마에서 뺀다. 기존 데모 값(testuser 2, alice 1)은 마이그레이션에서 버린다(§6). |
| D5 | 접근 1 — 공유 모듈 + IdP 공개 | 스키마와 인코더는 `lib/mode3_attr_schema.js` 하나를 IdP·지갑·RP 가 같이 쓰고, IdP 가 `GET /cia/attr_schema` 로 공개한다. 스키마 해시를 IdP 서명에 묶지는 않는다(회로 변경이 필요해 D3 와 맞지 않음 — §8 한계). |

## 3. 스키마

### 3.1 형식

```json
{
  "id": "zkd-attrs",
  "version": 1,
  "slots": [
    { "name": "<식별자>", "label": "<표시 이름>", "type": "int|enum|string|unused", ... },
    ... 정확히 6개(ATTR_SLOTS) ...
  ]
}
```

| 타입 | 추가 필드 | 인코딩(§4) | 허용 술어 |
|---|---|---|---|
| `int` | `min`, `max`(선택, 기본 0 ~ 2^64−1) | 10진 정수 그대로 | 범위, 집합 |
| `enum` | `values`: `{ "<이름>": <코드> }` — 코드는 서로 다르고 0 < 코드 < 2^64 | 이름 → 코드 | 집합 |
| `string` | `maxBytes`(선택, 기본·상한 124) | 빈 값 0, 아니면 64비트 해시 | 집합(같음 포함) |
| `unused` | — | 항상 0 | 없음 |

- **검증 규칙**(스키마를 읽을 때 한 번): 슬롯이 정확히 6개, `name` 은 `^[a-zA-Z][a-zA-Z0-9_]*$` 이고 서로 다름(`unused` 는 이름 없음 허용), `int` 의 `0 ≤ min ≤ max < 2^64`, `enum` 코드의 유일성·범위(0 은 "값 없음"으로 예약), `string.maxBytes ≤ 124`. 어기면 기동 실패.
- **스키마 해시**: 키를 정렬한 정규 JSON(공백 없음)의 SHA-256 16진. `id`·`version`·`hash` 를 함께 내보낸다.

### 3.2 기본 스키마 (`zkd-attrs` v1)

| 슬롯 | name | label | type | 비고 |
|---|---|---|---|---|
| a₀ | `birthYear` | 출생연도 | int, 1900 ~ 2100 | 범위 술어(나이 조건) |
| a₁ | `country` | 국가 | enum | ISO 3166-1 숫자 코드. KR 410, JP 392, US 840, DE 276, FR 250(현행 데모·RP 기본 정책), GB 826, CN 156, CA 124, AU 36, SG 702 |
| a₂ | `extra1` | 예비 1 | string | |
| a₃ | `extra2` | 예비 2 | string | |
| a₄ | — | — | unused | 회로 슬롯만 있고 쓰지 않음(D3) |
| a₅ | — | — | unused | 〃 |

- `AttrGate`(불변 컨트랙트)는 "출생연도 = 슬롯 0, 국가 집합 = `set_sel 2`(슬롯 1)"을 코드에 박고 있다. 기본 스키마는 이 위치를 지키고, 다른 스키마가 `birthYear`·`country` 를 다른 슬롯에 두면 RP 는 AttrGate 배포를 거절한다(§5.4).
- 스키마 파일 위치: 기본값은 `lib/mode3_attr_schema.js` 안의 상수. IdP 는 `CIA_ATTR_SCHEMA_FILE`(선택)로 다른 JSON 을 쓸 수 있다.

## 4. 인코딩·디코딩

공통: 결과는 **정규 10진 문자열**(앞자리 0 없음, `"0"` 은 그대로). 지금의 저장·전송·변경 감지(`JSON.stringify` 비교)와 그대로 맞물린다.

- **int**: 입력은 `^[0-9]+$` 문자열(앞뒤 공백 제거 후) 또는 안전한 정수(`Number.isSafeInteger`, 아니면 오류). 빈 값은 0("값 없음")이고 `min` 과 무관하게 허용한다(속성이 없는 계정). 나이 술어는 RP 가 `lo ≥ min` 을 함께 요구해 0 을 배제한다(온체인 AttrGate 는 hi 만 봄 — 한계). 관리자 입력에서는 min > 0 인 슬롯의 빈 값을 거절한다(`bad_attr` 이유 `empty`, 2026-10-07 최종 리뷰 I1). 빈 값이 아니면 `[min, max]` 를 벗어날 때 오류.
- **enum**: 입력은 스키마의 이름(대소문자 구분). RP 정책·관리자 입력은 코드 숫자도 받는다(그 코드가 표에 있어야 함). 빈 값은 0(관리자 입력에서는 int 와 같이 거절). 관리자가 저장하는 `profile` 은 이름으로 정규화한다(코드 `410` → `KR`). 디코드는 코드 → 이름(표에 없는 코드는 `#<코드>` 로 표시만 하고 오류는 아님).
- **string**:
  - 입력의 앞뒤 공백을 제거한 뒤(내부 공백은 유지) NFC 로 정규화하고 UTF-8 바이트로 바꾼다. 빈 문자열은 0. `maxBytes` 초과는 오류.
  - 바이트를 31바이트씩 잘라 큰 끝(big-endian) 정수로 만든 조각 c₀…c₃(모자라면 0).
  - `h = Poseidon(DOMAIN_MODE3_ATTRSTR, slotIndex, byteLength, c₀, c₁, c₂, c₃)`, `DOMAIN_MODE3_ATTRSTR` = ASCII `"MODE3ATTRSTR"` 의 정수.
  - 값 = `(h mod (2^64 − 1)) + 1` — 항상 1 이상 2^64 미만이라 빈 값(0)과 겹치지 않고 집합 트리의 빈칸 표시(`SET_PAD = 2^64`)와도 겹치지 않는다.
  - 디코드는 불가(일방향). 표시는 IdP 가 보관한 원래 값(`profile`)으로 한다.
- **unused**: 입력이 비어 있거나 0 이어야 하고 결과는 0.
- **술어 인코딩**: RP 정책·지갑 요청의 집합 원소도 같은 슬롯의 인코더로 바꾼다(국가 `KR,JP` → `410, 392`). 범위 술어의 `lo/hi` 는 int 슬롯에서만 받는다.

## 5. 구성 요소별 변경

### 5.1 공유 모듈 `lib/mode3_attr_schema.js` (새)
- `DEFAULT_ATTR_SCHEMA`, `loadSchema(json) → {schema, hash}`(§3.1 검증), `encodeProfile(schema, profile) → string[6]`, `decodeAttrs(schema, attrs, profile?) → [{name,label,type,value,display}]`, `encodeSlotValue(schema, slotIndex, value)`, `slotIndexOf(schema, name)`, `allowedPredicates(schema, slotIndex) → {range, set}`.
- 외부 의존 없음(Poseidon 은 기존 `circomlibjs`).

### 5.2 IdP (`cia.js`, `lib/mode3_cia_state.js`)
- 계정: `profile`(원래 값, 스키마 이름 → 문자열)을 정본으로 두고 `attrs` 는 `encodeProfile` 로 만든다. 데모 계정: testuser `{birthYear: "1990", country: "KR"}`, alice `{birthYear: "2005", country: "US"}`(등급 제거, D4).
- `GET /cia/attr_schema` → `{ schema, hash }`(공개, 인증 없음). `/mode3/health` 에 `attrSchema: {id, version, hash}` 를 더한다.
- 등록 응답·`POST /cia/attrs` 응답에 `profile`·`schemaHash` 를 더한다(`attrs` 는 그대로 — 지갑·Snap 호환).
- 관리자 속성 변경 `POST /cia/accounts/:uid/attrs` 는 `{ profile }` 만 받는다. 인코딩 오류는 400(`bad_attr` + 슬롯·이유). 성공하면 지금과 같은 경로(활성 자격증명 은퇴 → 슬롯 0 → 게시). 예전 `{ attrs: [...] }` 형식은 400 `use_profile`.
- `GET /cia/accounts` 는 `profile` 도 내보낸다.

### 5.3 지갑 (`mode3_wallet_agent.js`, `lib/mode3_wallet.js`)
- 기동 때(그리고 등록·동기화 때) IdP 에서 스키마를 받아 둔다. IdP 가 응답에 실은 `schemaHash` 와 다르면 경고를 찍고 다시 받는다.
- 증명·커밋에 쓰는 값은 지금처럼 인코딩된 `attrs`. 상태에 `profile` 을 함께 둔다(표시용, 선택 필드 — 상태 버전은 올리지 않는다).
- 로그인·tx 요청의 `disclose`/`set` 을 스키마로 검사한다: 범위 술어는 int 슬롯에만, 집합 술어는 int·enum·string 슬롯에만. 어기면 400 `predicate_type`. 요청 형식(숫자 lo/hi, 숫자 집합 원소)은 그대로 두고 화면이 이름 ↔ 코드를 바꾼다.
- `/wallet/status` 에 `profile`·`attrSchema`(id·version·hash)를 더한다.

### 5.4 RP (`mode3_rp.js`, `lib/mode3_onchain.js`)
- `MODE3_ALLOWED_COUNTRIES` 는 이름(`KR,JP`)과 코드(`410,392`)를 모두 받아 `country` 슬롯 인코더로 바꾼다. 표에 없는 이름·코드는 기동 실패(지금도 숫자가 아니면 기동 실패한다).
- 국가·출생연도 슬롯 번호를 스키마의 `country`·`birthYear` 로 찾는다(지금의 `d.sel === 2n`, `mask & 1` 하드코딩을 슬롯 번호에서 계산). 스키마에 두 필드가 없으면 해당 술어 요구(`require.countrySet`/`minAge`)를 거절한다.
- `AttrGate` 배포는 `birthYear` 가 슬롯 0, `country` 가 슬롯 1 일 때만(컨트랙트가 불변이고 그 위치를 박고 있다). 아니면 경고와 함께 배포를 건너뛴다.
- `rp_info.predicates` 에 `allowedCountryNames`·`attrSchema`(id·version·hash)를 더한다(숫자 필드는 그대로).
- `ALLOWED_COUNTRIES_DEFAULT`(숫자)는 그대로 — 기본 스키마의 코드와 같다.

### 5.5 Snap (`snap-mode3/src/index.js`)
- 내부 표현은 그대로(10진 문자열 6개, `isDec` 검사 유지). 슬롯 이름표 `SLOT_LABELS` 만 기본 스키마에 맞춘다(출생연도, 국가, 예비 1, 예비 2, 미사용, 미사용). 스키마를 RPC 로 받는 것은 비범위(§10).

### 5.6 화면 (`mode3/cia_admin.html`, `mode3/wallet.html`, `mode3/rp.html`, `mode3/common/strings.js`)
- 관리자: 계정 행의 속성 입력을 스키마로 그린다 — int 숫자 입력, enum 선택 목록(이름), string 글자 입력, unused 는 숨김. `{profile}` 로 저장.
- 지갑: 속성 행·조건 표시를 스키마로 풀어 보여 준다(예: "국가 ∈ {KR, JP}", "출생연도 ≤ 2007 (나이 ≥ 19)"). 선택 공개 입력의 슬롯 선택·집합 원소도 이름으로.
- RP: 정책 문구를 이름으로(국가 ∈ {KR, JP}).
- `strings.js` 의 `attr0..attr5` 용어·`admin_col_attrs` 를 새 스키마에 맞춘다(등급 제거, 예비 1·2, 미사용). Snap·wallet.html 의 중복 이름표도 같이 맞춘다.

### 5.7 문서
- `docs/MODE3_DEMO.md` "속성과 선택 공개" 절: 스키마·인코딩·데모 값·`/cia/attr_schema`·RP 정책 이름 형식. 낡은 `disclose ×4` 문구(실제는 1~6)도 고친다.
- V9 스펙 §13 의 "스펙 2" 항목에 이 문서를 가리키는 한 줄.

## 6. 마이그레이션

- **IdP 상태 v10 → v11** (`lib/mode3_cia_state.js`):
  - 계정마다 기존 `attrs` 를 기본 스키마로 풀어 `profile` 을 만든다: 슬롯 0 → `birthYear`(0 이면 빈 값), 슬롯 1 → 국가 이름(표에 없는 코드는 빈 값 + 경고 로그).
  - 슬롯 2(예전 등급)·3·4·5 의 0 아닌 값은 새 스키마로 표현할 수 없으므로 버린다(빈 값/0) + 경고 로그. 예전 예비 슬롯 값은 원래 문자열을 알 수 없기 때문이다.
  - 새 `attrs = encodeProfile(profile)`. 예전 `attrs` 와 다르면 그 계정에 "속성 변경" 표시를 남기고, 기동 직후 관리자 속성 변경과 같은 경로(활성 자격증명 은퇴 → 등록부 슬롯 0 → 게시)를 탄다. 지갑은 다음 로그인 때 기존 자동 재동기화(`bad user credential proof` → `/cia/attrs` → 재발급)로 새 자격증명을 받는다.
  - 데모 계정 testuser·alice 는 등급 슬롯이 0 이 아니므로 이 경로를 탄다(속성 변경 1회).
- **지갑 상태·Snap 상태**: 형식이 그대로라 버전을 올리지 않는다(`profile` 은 선택 필드).
- 되돌리기: v11 → v10 으로 내리는 경로는 두지 않는다(기존 마이그레이션 관례와 같음). 상태 파일은 기동 전에 백업하라고 런북에 적는다.

## 7. 오류 처리

| 상황 | 어디 | 응답 |
|---|---|---|
| 스키마 검증 실패(§3.1) | IdP 기동(`CIA_ATTR_SCHEMA_FILE`)·RP 기동(CIA 가 준 스키마) | 기동 실패, 위반 항목을 메시지에 |
| CIA 에 닿지 못함(HTTP 오류·네트워크) | RP 기동·지갑 | 기본 스키마 + 경고(RP 는 프로세스 수명 동안, 지갑은 60초 간격 백그라운드 재수신) |
| CIA 가 준 스키마가 검증 실패 | 지갑 | 보관 스키마를 바꾸지 않고 오류 로그, 술어가 있는 `/wallet/login`·`/wallet/tx` 는 503 `schema_invalid`(술어 없는 요청은 그대로) |
| 데모 계정 profile 이 스키마로 인코딩되지 않음(없는 키는 버리고 없는 int·enum 키는 빈 값으로 채운 뒤) | IdP 기동 | 기동 실패 |
| 상태 파일의 `attrSchemaHash` 와 지금 스키마의 해시가 다름 | IdP 기동 | 기동 실패(다시 인코딩하는 경로는 비범위 — 스키마를 되돌리거나 상태 파일을 새로 시작) |
| 관리자 입력 인코딩 실패(표에 없는 enum, int 범위 밖, string 너무 김, unused 에 값, min > 0 인 int·enum 의 빈 값) | `POST /cia/accounts/:uid/attrs` | 400 `{error:'bad_attr', slot, reason}`(빈 값은 reason `empty`) |
| 관리자 입력의 `attrs` 가 지금과 같음(예: `410` ↔ `KR`) | 〃 | 200, `profile` 만 저장, `retired: 0`(자격증명 유지) |
| 예전 배열 형식 입력 | 〃 | 400 `use_profile` |
| 범위 술어를 int 아닌 슬롯에, 집합 술어를 unused 슬롯에 | 지갑 `/wallet/login`·`/wallet/tx` | 400 `predicate_type` |
| RP 정책 국가가 표에 없음 | RP 기동 | 기동 실패 |
| 스키마에 `country`/`birthYear` 없음 | RP 로그인 술어 요구 | `predicate_unavailable`(로그인은 거절) |
| 나이 술어의 `lo` 가 스키마의 출생연도 min 보다 작음 | RP 로그인 술어 요구(`minAge`) | `predicate_unmet` |
| 지갑이 받은 `schemaHash` 와 보관 스키마 불일치 | 지갑 | 경고 후 재수신 |

## 8. 보안·프라이버시 메모

- **스키마는 서명에 묶이지 않는다(D5).** IdP 가 스키마의 의미(예: enum 표)를 몰래 바꾸면 같은 숫자가 다른 뜻이 될 수 있다. 완화: 스키마 해시를 IdP 가 공개하고 RP·지갑이 기동 때 받아 보관·표시하며 바뀌면 경고. 서명에 해시를 넣는 것은 회로 변경이 필요해 비범위(§10).
- **문자열 해시는 64비트**: 서로 같은 값을 내는 두 문자열(생일 충돌)은 약 2^32 번의 시도로 찾을 수 있고, 주어진 값과 같은 값을 내는 다른 문자열(2차 원상)은 약 2^64 번이 든다(2026-10-07 최종 리뷰에서 둘을 구분). 속성 값은 IdP 가 정하고 사용자가 고를 수 없으므로 프로토타입에서는 위험이 작다고 보되 이 한계를 문서·논문에 적는다. 정수·enum 슬롯은 해당 없음.
- **RP 가 보는 것은 바뀌지 않는다**: RP 는 지금처럼 술어(범위·집합)만 본다. `profile`(원래 값)은 IdP 와 그 사용자의 지갑만 갖는다.
- **enum 코드를 ISO 숫자로 두는 선택(D2)** 은 코드에서 국가를 추측할 수 있게 하지만, 집합 술어가 공개하는 것은 "집합 안에 있다"뿐이라 공개 범위는 지금과 같다.

## 9. 테스트·검증

- **새 단위 테스트** `tests/test_mode3_attr_schema.mjs`(`unit` 그룹): 스키마 검증 실패 사례, int·enum·string·unused 왕복, 정규 10진, string 해시 범위(1 ~ 2^64−1)·슬롯 분리·NFC·최대 길이, 빈 값, enum 코드 입력, 허용 술어 표.
- **IdP**: v10 → v11 마이그레이션(`test_mode3_cia_state*.js` 확장 — testuser·alice 등급 제거, 알 수 없는 코드, 예전 예비 슬롯 값), `/cia/attr_schema`, 관리자 `{profile}` 변경과 오류 응답(`test_cia_register_issue.mjs`).
- **RP**: `MODE3_ALLOWED_COUNTRIES=KR,JP` 와 `410,392` 가 같은 set root 를 내는지, 표에 없는 이름에서 기동 실패(`test_mode3_rp.mjs`).
- **지갑**: `predicate_type` 거절(`test_mode3_wallet_agent.mjs`).
- **데모 값 변경 반영**: testuser 의 등급 2 를 박아 둔 테스트·픽스처(`tests/helpers/mode3_fixture.mjs` 등 약 20개)를 새 인코딩 값으로. 회로·컨트랙트 테스트의 임의 속성 벡터(`[19n,410n,0n,…]` 등)는 스키마와 무관하므로 그대로.
- **회귀**: `npm test`(unit + circuit), `contract`, `chain`, `browser`, `snap` 전부. 마지막에 `tests/test_mode3_demo_full.mjs`(두 체인, 거래소 `KR,JP` 정책)로 전 구간 확인.
- 회로·zkey·검증 컨트랙트는 바뀌지 않으므로 성능 재측정은 하지 않는다(D3).

## 10. 비범위·후속

- 스키마 해시를 IdP 서명·회로 공개 입력에 묶기(스키마 바꿔치기를 증명 수준에서 막음) — 회로 변경.
- 속성 슬롯 수를 실제로 4개로 줄이기(D3 의 "논리적 6개"를 물리적으로) — 회로 변경, 공개 입력 30 → 26.
- `date` 타입(epoch 일수), 구조체 펼치기.
- Snap 이 스키마를 RPC 로 받아 이름표·조건 문구를 스키마로 그리기.
- IdP 하나가 여러 스키마(서비스별)를 운영하기.

## 11. 남는 질문

없음(기본 국가 표는 §3.2 에서 확정).
