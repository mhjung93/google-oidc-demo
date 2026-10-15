// mode3/user/prover_client.js — 메인 스레드의 워커 클라이언트. lib 가 넘기는 (input, wasmPath, zkeyPath) 중 input 만 보낸다(계획 R7).
export function createProver({ workerUrl = '/dist/prover_worker.js', onProgress = () => {} } = {}) {
  const worker = new Worker(workerUrl, { type: 'module' });
  const pending = new Map(); let seq = 0;
  worker.onmessage = ({ data }) => {
    if (data?.kind === 'progress') return onProgress(data);
    const p = pending.get(data?.id); if (!p) return; pending.delete(data.id);
    if (data.error) p.reject(Object.assign(new Error(data.error), { reason: data.reason ?? 'zk_assets_unavailable' }));
    else p.resolve(data);
  };
  worker.onerror = (e) => { for (const p of pending.values()) p.reject(Object.assign(new Error(e.message ?? 'worker error'), { reason: 'zk_assets_unavailable' })); pending.clear(); };
  const call = (msg) => new Promise((resolve, reject) => { const id = ++seq; pending.set(id, { resolve, reject }); worker.postMessage({ id, ...msg }); });
  const prove = (kind) => async (input) => { const { proof, publicSignals } = await call({ kind, input }); return { proof, publicSignals }; };
  return { fullProve: { idp: prove('pi_idp'), cred: prove('pi_cred') }, warm: (which) => call({ kind: 'warm', which }) };
}
