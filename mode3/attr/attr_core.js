// mode3/attr/attr_core.js — 속성 커밋먼트 도구(mode3/attr.html)의 브라우저 번들 엔트리(2026-11-09 Phase 1). `npm run attr:build` →
// mode3/attr/dist/attr.js (IIFE, window.Mode3Attr). 공유 lib 를 그대로 묶는다 — 인코딩(lib/mode3_attr_schema.js)과 커밋먼트
// (lib/mode3_attr_commit.js)가 Node(테스트·지갑)와 같은 코드다. 네트워크 호출은 없다 — 이 페이지는 아무 서버와도 말하지 않는다.
export { DEFAULT_ATTR_SCHEMA, encodeProfile, normalizeProfile, decodeAttrs } from '../../lib/mode3_attr_schema.js';
export { attrCommit, randomBlind, isAttrCommit, DOMAIN_MODE3_ATTRC } from '../../lib/mode3_attr_commit.js';
export { auidOf } from '../../lib/mode3_credential.js';   // 2026-11-11: 같은 uid·salt 로 auid 를 보인다(첫 RP 로그인 인증 창에 붙여 넣는 값)
