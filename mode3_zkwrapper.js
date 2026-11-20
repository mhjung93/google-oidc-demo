// mode3_zkwrapper.js — zkWrapper 서버 진입점(스펙 2026-11-20 zkwrapper §1·§4). 사용자가 접속하는 한 서버(기본 :5100)다:
//   · 사용자 앱(홈·승인 창·속성 도구·회로 파일·공개 설정) — 브라우저 지갑. 비밀(salt·세션키)은 서버로 오지 않는다.
//   · 발급 API(래퍼 방식) — Google ID 토큰을 받아 세션 토큰으로 바꿔 준다. 별도 IdP(계정·비밀번호·인증 창·π_IdP)가 없다.
//   · 서비스 등록·관리자·개봉은 지금까지의 발급 서버와 같다.
// 구현은 cia.js 다 — 여기서는 깃발만 세우고 띄운다. 체인 읽기는 이 서버를 거치지 않는다: 브라우저가 MODE3_CHAIN_RPC_BROWSER(응용 체인)·MODE3_REV_RPC_BROWSER(폐기 체인)의
// 노드를 직접 부른다(이 서버가 "누가 어느 서비스의 계정을 읽는가" 를 보지 않게 — 스펙 §5).
//   MODE3_ZKWRAPPER_PORT(기본 5100) · CIA_PUBLIC_URL(사람이 여는 주소 — https 이름 또는 localhost) · MODE3_OIDC_CLIENT_ID(래퍼 전용 Google 클라이언트 ID) ·
//   MODE3_OIDC_REDIRECT_URI(Google 에서 돌아올 주소 — 이 서버의 /google-relay) · MODE3_RP_GOOGLE_CLIENT_ID_DENY(서비스들의 Google 클라이언트 ID — 같으면 기동 거부)
process.env.CIA_WRAPPER = '1';
process.env.CIA_USER_APP = '1';
if (!process.env.CIA_PORT) process.env.CIA_PORT = process.env.MODE3_ZKWRAPPER_PORT || '5100';
if (!process.env.MODE3_WALLET_KIND) process.env.MODE3_WALLET_KIND = 'zkwrapper';   // 화면 문구 — 지갑은 브라우저의 zk 클라이언트이고, 별도 IdP 가 없다(/mode3/health 의 walletKind)
await import('./cia.js');
