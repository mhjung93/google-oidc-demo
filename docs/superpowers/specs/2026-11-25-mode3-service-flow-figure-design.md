# Mode 3 — 서비스 화면에서 여는 로그인 플로우 그림 (설계 초안)

- 작성: 2026-11-25. 상태: **승인(2026-11-25 "전부 추천대로")·구현, 미커밋·라이브 서비스 VM 미반영**.
- 목적: 서비스(zkONE·zkTWO)가 **실제로 받은 값**으로 `/common/flow.html` 을 채운다. Google 로그인이면 `sub`·`aud` 가 그대로, zkWrapper 로그인이면 가명과 PPID 만 — 이 대비를 실제 값으로 보인다.
- 범위: zkWrapper 만(`rp_info.walletKind === 'zkwrapper'`). 다른 방식의 서비스에서는 지금과 같다(링크 없음·빈 그림). 서버(`mode3_rp.js`)·회로·컨트랙트는 바꾸지 않는다.

## 1. 확인한 사실 (2026-11-25, 코드 + 라이브 읽기 요청)

| 사실 | 근거 |
|---|---|
| 서비스의 `/common/flow.html` 은 200, `/user/config` 는 404 | 라이브 zkONE |
| `walletKind` 는 `/mode3/health` 와 `/api/mode3/rp_info` 둘 다에 있다. `/api/rp/info` 라는 경로는 없다(404) | 라이브, `mode3_rp.js:513` |
| `/mode3/health` 는 부를 때마다 체인을 읽는다(최대 1.2초). `rp_info` 는 읽지 않고 이름(`name`)도 준다 | `mode3_rp.js:513-531` |
| :5100 에는 `rp_info`·`/api/rp/me` 가 없다(404) — 오리진 구분에 쓸 수 있다 | 라이브 |
| `/api/rp/me` 는 zk 세션이면 부를 때마다 체인을 읽고, 만료된 세션은 지운다. 닫힌 세션이면 401 | `zkidCookieAlive` |
| `seen` 은 Google·zkid·zkoidc 에만 있다. 네이버는 null. 로그인 시각은 없다 | `seenOf` |
| 서비스가 Google 에 청하는 범위는 `openid` 뿐이고, **zkWrapper 는 `openid email`** 이다 | `rp.html:926`, `idp_return.js:72` |
| zkWrapper 의 uid 는 `SHA-256("provider\|sub")` 에서 만든다. 확인된 이메일은 계정의 아이디(`loginId`)로 **저장한다** | `mode3_oidc_nonce.js:20`, `cia.js` `issueWrapper` |
| 그림에 `salt` 값 칸은 없다(② 의 설명 글자뿐). 윗줄에는 값을 넣을 칸(id)이 아예 없다 | `flow.html` |
| 그림은 `strings.js` 를 읽지 않는다 — 글자는 한국어로 박혀 있고 래퍼 용어는 `flow_page.js` 의 `W()` 가 바꾼다 | `flow.html`, `flow_page.js` |

## 2. 설계

### 2.1 어느 오리진인가
1. `/user/config` 가 열리면 **지갑 오리진** — 지금 코드 그대로. 새 요청을 하나도 보내지 않는다.
2. 아니면 `/api/mode3/rp_info` 를 읽어 `walletKind === 'zkwrapper'` 이면 **서비스 오리진**. `WRAP = true` 로 두어 글자를 래퍼 용어로 맞춘다.
3. 둘 다 아니면 지금과 같다.

"`/user/config` 가 없으면 서비스" 로 판정하지 않는다 — :5100 의 일시 오류가 서비스로 오인된다. 판정은 `rp_info` 가 실제로 답했는지로 한다. `/mode3/health` 대신 `rp_info` 를 쓰는 이유는 체인을 읽지 않고 서비스 이름까지 주기 때문이다.

### 2.2 무엇을 채우나 (지금 로그인한 방식의 줄만)

| `seen` | 윗줄(일반 OIDC) | 아랫줄(zk) |
|---|---|---|
| Google | ① `client_id` = `rid`, ③ `sub` = `uid` · `aud` = `rid`(`iss` 전체는 title) | 이름만 |
| zk | 이름만 | `auid_s`·`arid_s`·`PPID` |
| 없음(로그아웃·닫힘·네이버)·zkoidc | 이름만 | 이름만 |

- zkoidc 를 채우지 않는 이유: 윗줄의 이름이 "Google 로 로그인" 이다.
- uid 자리(`#zkUid`)는 " — 이 서비스는 모름", ② 의 괄호는 "(이 서비스는 모름)".
- **③ 은 서비스가 보지 못하는 구간이다.** 거기 적히는 `auid_s`·`arid_s` 는 서비스가 ⑤ 로 받은 같은 값이라고 설명에 적는다.
- 단계별 시간 표와 "전체 …ms" 는 만들지 않는다. "로그인한 뒤에 채워집니다" 안내도 서비스에서는 내지 않는다.
- 값은 `textContent` 로만, 앞 17자 + 전체는 title. `jwt` 본문은 그림에 쓰지 않는다(`iss` 하나만).
- 어디에도 저장하지 않는다(localStorage·sessionStorage·IndexedDB·주소). 서비스 오리진에서는 `readFlow()` 를 부르지 않는다.

### 2.3 그림 파일
- 윗줄에 빈 글자 칸을 더한다: ① 아래 `#oidcClientId`(y=108), ③ 아래 `#oidcSub`·`#oidcAud`(y=214), 줄 머리 `#recentOidc`(hidden). 지갑 오리진에서는 비어 있어 배치가 그대로다(viewBox 를 바꾸지 않는다).
- "zkTWO 도 같은 값" 은 박힌 글자라 zkTWO 에서 열면 틀린다 → 서비스 오리진에서만 "다른 서비스" 로 바꾼다.
- 맨 아래 "서비스 화면의 '알려 준 것' 칸"·`/#flowCard` 안내는 서비스에서 맞지 않는다 → 서비스 오리진에서는 "이 서비스가 받은 실제 값" 문장으로 바꾸고 링크를 뺀다.
- 머리말(`#hdrNote`)은 서비스 이름.

### 2.4 갱신
열 때 한 번, 탭으로 돌아올 때 한 번. **2초 폴링은 하지 않는다** — `/api/rp/me` 는 매번 체인을 읽는다(서비스 화면도 10초 간격이다). 늦게 온 응답이 새 값을 덮지 않게 마지막 요청만 쓴다. 401 이면 그려 둔 값을 **지운다**.

### 2.5 서비스 화면 링크
`#seenBox` 안에 `<a id="flowFigureLink" href="/common/flow.html" target="_blank" rel="noopener">`. `walletKind === 'zkwrapper'` 일 때만 보인다. 문구 `rp_flow_link`(ko "로그인 플로우 그림" / en "Login flow figure"). 바뀔 용어가 없어 `ko_wr` 변형은 두지 않는다. 그림 안 글자는 지금처럼 `flow_page.js` 에 둔다(영어판은 이 작업의 범위가 아니다).

## 3. 그림의 주장이 사실과 맞는가

1. **"zkWrapper 가 알게 되는 것: 누가 로그인했는지 (uid)"** — 틀리지는 않지만 모자란다. zkWrapper 는 Google `sub` 와 이메일을 받는다. 윗줄의 uid(= sub)와 아랫줄의 uid(= sub 의 해시)는 **이름만 같고 값이 다르다.** 제안: "누가 로그인했는지 — Google 의 **sub 와 이메일**을 받는다 (uid 는 sub 의 해시)".
2. **"어느 서비스인지 모른다"** — 로그인 때는 맞다. 그 로그인이 **온체인 거래로 이어지면 맞지 않는다**: 거래의 공개 입력에 `arid`·`PPID`·`auid_s` 가 함께 있고 zkWrapper 는 `auid_s` 기록을 갖고 있다(`2026-11-19-mode3-trace-without-tag-design.md` §3). 제안: "로그인 때는 **어느 서비스**인지 모른다 (온체인 거래를 하면 공개 입력으로 이어질 수 있다)". 맨 아래 "평소에는 두 기록이 따로 있어 이어지지 않습니다" 에도 같은 단서를 단다.
3. **"매번 다른 가명만"** — `auid_s`·`arid_s` 는 로그인마다 다르지만 **PPID 는 같은 서비스에서 늘 같다.** 새 문구에서 PPID 를 매번 다르다고 적지 않는다.

## 4. 검증
- `:5100` 회귀: 기존 "전체 플로우 한 장" 사례가 그대로 통과하고, 그 페이지가 `/api/rp/me`·`/api/mode3/rp_info` 를 **부르지 않는다**는 단언을 더한다.
- zkONE, Google 로그인 뒤: 윗줄 `sub`·`aud`·`client_id` 의 title 이 `/api/rp/me` 와 같다. 아랫줄은 이름만.
- zkONE, zkWrapper 로그인 뒤: `auid_s`·`arid_s`·`PPID` 의 title 이 같다. 윗줄은 이름만이고, **앞서 로그인한 Google `sub` 가 문서 어디에도(속성·title 포함) 없다.** 시간 표가 없다.
- 두 번 로그인: `auid_s`·`arid_s` 는 달라지고 `PPID` 는 같다.
- 로그아웃 뒤 탭으로 돌아오면 값이 지워진다. 저장소에 새 항목이 없다.
- 용어: 화면에 `zkIdP`·`zk 클라이언트`·`zk 로그인` 이 없다. `tests/test_mode3_demo_strings.js` 통과.
- 문법: `node --check mode3/common/flow_page.js`, `rp.html` 인라인은 `vm.Script`.
- 라이브 반영: `rp.html`·`flow.html`·`flow_page.js` 는 서비스 VM 에도 있어야 한다(SYNC 재기동 = 데모 계정 초기화, 또는 파일만 복사).

## 5. 하지 않는 것
두 줄 동시 채우기, 앞 로그인 값 보관, 서비스에서의 시간 표시, zkoidc·네이버 채우기, 그림의 영어판, 서버 API 변경.

## 6. 정한 것 (2026-11-25)
- **Q1.** §3 의 1·2 는 래퍼 방식이면 :5100 과 서비스 두 곳 모두 고친다.
- **Q2.** 그림 맨 아래 링크는 래퍼 방식의 :5100 에서 `/user#flowCard` 로 바꾼다(서비스에서는 링크 없음).

## 7. :5100 에서 토큰 값 보기 (2026-11-25 사용자 추가 요청)
- ③ 을 누르면 그 로그인의 **Google ID 토큰** 본문, ④ 를 누르면 **세션 토큰**(zkWrapper 가 낸 JWT) 본문과 함께 서명된 값(`auid_s`·`arid_s`·`C_u`·`C_s`·`chainid`·`allowAgent`)을 편다. 값은 줄이지 않는다.
- 지갑의 로그인 기록(kv `loginFlow`)의 `values.tokens` 에 머리의 `alg`·`kid` 와 정해진 클레임(`iss azp aud sub email email_verified nonce iat exp`)만 남긴다. **서명과 원문은 남기지 않는다** — 기록으로는 토큰을 다시 낼 수 없다. 자격증명 서명 σ 도 싣지 않는다.
- 가장 최근 로그인 하나만 남고 `loginFlow` 를 지우는 동작(모두 지우기 등)에서 함께 사라진다. 이 기록이 생기기 전의 로그인에는 "다음 로그인부터 보입니다" 를 보인다.
- **대가**: 이 브라우저의 IndexedDB 에 Google `sub` 와 이메일이 평문으로 남는다(전에는 `sub` 의 해시인 uid 뿐이었다). `/common/flow.html` 은 `/user` 의 패스키 화면 잠금 밖이다.
- 서비스 오리진에는 토큰 표가 없다.
