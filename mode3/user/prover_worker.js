// mode3/user/prover_worker.js — 증명 워커(스펙 §6). 메인 스레드는 입력만 보내고 zkey 는 여기서만 산다. kind 마다 첫 증명 뒤 vkey 로 한 번 자기 검증한다(산출물 짝 확인 — 에이전트의 artifacts 검사 대체).
import * as snarkjs from 'snarkjs';
import { loadSet, loadJson } from '../../lib/browser/zk_assets.js';
const ASSETS = { pi_idp: { wasm: '/zk/pi_idp.wasm', zkey: '/zk/pi_idp_final.zkey', vkey: '/zk/pi_idp_vkey.json' }, pi_cred: { wasm: '/zk/pi_cred.wasm', zkey: '/zk/pi_cred_final.zkey', vkey: '/zk/pi_cred_vkey.json' } };
const loaded = {}, verified = {}, vkeys = {};
function assets(kind) {
  return (loaded[kind] ??= (async () => {
    const a = ASSETS[kind]; if (!a) throw Object.assign(new Error(`모르는 kind ${kind}`), { reason: 'zk_assets_unavailable' });
    const onProgress = (p) => self.postMessage({ kind: 'progress', name: kind, ...p });
    // 세트의 버전(= 서버에서 새로 받은 vkey 의 해시)이 캐시 키에 들어간다 — 회로를 다시 만들면 옛 zkey·wasm 을 쓰지 않는다(2026-11-20, lib/browser/zk_assets.js)
    return loadSet(a, { onProgress });
  })().catch((e) => { delete loaded[kind]; throw e; }));
}
self.onmessage = async ({ data }) => {
  const { id, kind, input, which } = data ?? {};
  try {
    // 검증(2026-11-18 증명 기록 화면): 기록된 증명을 그 종류의 검증키로 다시 본다 — zkey·wasm 은 받지 않는다. 공개 입력이 엉터리(범위 밖·숫자 아님)면 false.
    if (kind === 'verify') {
      const a = ASSETS[which]; if (!a) throw Object.assign(new Error(`모르는 kind ${which}`), { reason: 'zk_assets_unavailable' });
      const vkey = await (vkeys[which] ??= loadJson(a.vkey).catch((e) => { delete vkeys[which]; throw e; }));
      const t = Date.now(); let ok = false;
      try { ok = (await snarkjs.groth16.verify(vkey, data.publicSignals, data.proof)) === true; } catch { ok = false; }
      return self.postMessage({ id, ok, ms: Date.now() - t });
    }
    if (kind === 'warm') { await Promise.all((which ?? ['pi_idp', 'pi_cred']).map(assets)); return self.postMessage({ id, warmed: true }); }
    const a = await assets(kind);
    const t = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, a.wasm, a.zkey);
    if (!verified[kind]) {
      if (!(await snarkjs.groth16.verify(a.vkey, publicSignals, proof))) throw Object.assign(new Error(`${kind}: vkey 가 zkey 와 짝이 아니다(산출물 세트 불일치)`), { reason: 'zk_assets_unavailable' });
      verified[kind] = true;
    }
    self.postMessage({ id, proof, publicSignals, ms: Date.now() - t });
  } catch (e) { self.postMessage({ id, error: e?.message ?? String(e), reason: e?.reason ?? null }); }
};
