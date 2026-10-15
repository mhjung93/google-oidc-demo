// lib/browser/node_path.js — 'node:path' 자리. lib/mode3_wallet.js·mode3_idp_proof.js·mode3_onchain.js 가 기본 경로 상수를 만들 때 join 만 쓴다(값은 web 모드에서 쓰이지 않는다).
// 세 lib 모두 모듈 로드 시점에 import.meta.url 기준으로 기본 자산 경로를 top-level 에서 즉시 계산해 export 한다 — 브라우저 번들에서도 반드시 실행되므로,
// join 이 프로토콜의 "://"(콜론 뒤 슬래시 두 개)까지 뭉개면 조용히 깨진 URL 문자열을 만든다. 콜론 바로 뒤의 슬래시 묶음은 건드리지 않고 그 외 중복 슬래시만 하나로 줄인다.
const join = (...p) => p.filter((s) => s !== undefined && s !== null && s !== '').join('/').replace(/(^|[^:])\/{2,}/g, '$1/');
const dirname = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) || '/' : '.');
const basename = (p) => p.slice(p.lastIndexOf('/') + 1);
const resolve = (...p) => join(...p);
const path = { join, dirname, basename, resolve, sep: '/' };
export default path;
export { join, dirname, basename, resolve };
