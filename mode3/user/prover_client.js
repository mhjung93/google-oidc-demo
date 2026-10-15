// mode3/user/prover_client.js — 메인 스레드의 워커 클라이언트. lib 가 넘기는 (input, wasmPath, zkeyPath) 중 input 만 보낸다(계획 R7).
export function createProver({ workerUrl = '/dist/prover_worker.js', onProgress = () => {} } = {}) {
  const worker = new Worker(workerUrl, { type: 'module' });
  const pending = new Map(); let seq = 0;
  worker.onmessage = ({ data }) => {
    if (data?.kind === 'progress') return onProgress(data);
    const p = pending.get(data?.id); if (!p) return; pending.delete(data.id);
    // 워커가 직접 태그한 사유(자산 로딩·vkey 불일치)만 따른다 — 그냥 witness 생성 실패는 사유 없이 와서 guard() 의 500 internal 로 남는다.
    if (data.error) p.reject(Object.assign(new Error(data.error), { reason: data.reason ?? null }));
    else p.resolve(data);
  };
  // 이건 메시지가 아니라 워커 자체가 뜨지 못한 경우(스크립트 로드 실패 등)다 — 그 자체가 자산 문제이므로 항상 zk_assets_unavailable.
  worker.onerror = (e) => { for (const p of pending.values()) p.reject(Object.assign(new Error(e.message ?? 'worker error'), { reason: 'zk_assets_unavailable' })); pending.clear(); };
  const call = (msg) => new Promise((resolve, reject) => { const id = ++seq; pending.set(id, { resolve, reject }); worker.postMessage({ id, ...msg }); });
  const prove = (kind) => async (input) => { const { proof, publicSignals } = await call({ kind, input }); return { proof, publicSignals }; };
  return { fullProve: { idp: prove('pi_idp'), cred: prove('pi_cred') }, warm: (which) => call({ kind: 'warm', which }) };
}
