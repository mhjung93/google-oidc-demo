// lib/browser/node_path.js — 'node:path' 자리. lib/mode3_wallet.js·mode3_idp_proof.js·mode3_onchain.js 가 기본 경로 상수를 만들 때 join 만 쓴다(값은 web 모드에서 쓰이지 않는다).
const join = (...p) => p.filter((s) => s !== undefined && s !== null && s !== '').join('/').replace(/\/{2,}/g, '/');
const dirname = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) || '/' : '.');
const basename = (p) => p.slice(p.lastIndexOf('/') + 1);
const resolve = (...p) => join(...p);
const path = { join, dirname, basename, resolve, sep: '/' };
export default path;
export { join, dirname, basename, resolve };
