// lib/browser/node_fs.js — 브라우저 번들에서 'node:fs' 자리. lib/mode3_idp_proof.js(loadIdpVkey)·lib/mode3_onchain.js(readArtifact·verifyReferenceCode)가
// import 만 하고 web 모드 경로에서는 부르지 않는다 — 부르면 분명한 오류로 죽게 한다(조용히 빈 값을 주지 않는다).
const nope = (name) => () => { throw new Error(`fs.${name} 는 브라우저에서 쓸 수 없다(web 모드는 이 경로를 쓰지 않아야 한다)`); };
const fs = { existsSync: () => false, readFileSync: nope('readFileSync'), writeFileSync: nope('writeFileSync'), openSync: nope('openSync'), rmSync: nope('rmSync'), promises: { readFile: async () => nope('promises.readFile')() } };
export default fs;
export const { existsSync, readFileSync, promises } = fs;
