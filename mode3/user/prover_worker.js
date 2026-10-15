// mode3/user/prover_worker.js — 증명 워커(Task 9 가 채운다). 지금은 snarkjs 브라우저 빌드가 번들되는지만 본다.
import * as snarkjs from 'snarkjs';
self.onmessage = (ev) => { self.postMessage({ id: ev.data?.id ?? null, pong: true, hasGroth16: typeof snarkjs.groth16?.fullProve === 'function' }); };
