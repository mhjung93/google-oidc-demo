// lib/browser/node_url.js — 'node:url' 자리. fileURLToPath(new URL('..', import.meta.url)) 가 번들 URL 문자열을 그대로 받는다.
export const fileURLToPath = (u) => String(u);
export default { fileURLToPath };
