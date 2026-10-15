// mode3/user/prover_worker.js — 증명 워커(스펙 §6). 메인 스레드는 입력만 보내고 zkey 는 여기서만 산다. kind 마다 첫 증명 뒤 vkey 로 한 번 자기 검증한다(산출물 짝 확인 — 에이전트의 artifacts 검사 대체).
import * as snarkjs from 'snarkjs';
import { loadAsset, loadJson } from '../../lib/browser/zk_assets.js';
const ASSETS = { pi_idp: { wasm: '/zk/pi_idp.wasm', zkey: '/zk/pi_idp_final.zkey', vkey: '/zk/pi_idp_vkey.json' }, pi_cred: { wasm: '/zk/pi_cred.wasm', zkey: '/zk/pi_cred_final.zkey', vkey: '/zk/pi_cred_vkey.json' } };
const loaded = {}, verified = {};
function assets(kind) {
  return (loaded[kind] ??= (async () => {
    const a = ASSETS[kind]; if (!a) throw Object.assign(new Error(`모르는 kind ${kind}`), { reason: 'zk_assets_unavailable' });
    const onProgress = (p) => self.postMessage({ kind: 'progress', name: kind, ...p });
    const [wasm, zkey, vkey] = await Promise.all([loadAsset(a.wasm, { onProgress }), loadAsset(a.zkey, { onProgress }), loadJson(a.vkey)]);
    return { wasm, zkey, vkey };
  })().catch((e) => { delete loaded[kind]; throw e; }));
}
self.onmessage = async ({ data }) => {
  const { id, kind, input, which } = data ?? {};
  try {
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
