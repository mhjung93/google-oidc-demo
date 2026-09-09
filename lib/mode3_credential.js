// Mode 3 credential 프로토콜 유도값 — circuits/pi_cred.circom 과 JS 쪽이 반드시
// 일치해야 하는 계산만 모은다(커밋 C, 서명 메시지, PPID). 단일 책임: 이 세
// 함수 밖의 어떤 프로토콜 로직도 여기 두지 않는다.
//
// 인자 **순서**는 회로 배선의 일부다 — Poseidon은 인자 순서가 바뀌면 다른
// 해시가 나오므로, 여기서 순서를 바꾸면 회로와 어긋난다.
import { buildPoseidon } from 'circomlibjs';

export const DOMAIN_MODE3_CRED = 1426111059989523219780n; // ASCII "MODE3CRED" 빅엔디언

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// circuits/pi_cred.circom 의 commit 배선(uid, arid, s_u, blind, pk_i 순서)과
// 일치해야 한다.
export async function credCommit({ uid, arid, s_u, blind, pk_i }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, arid, s_u, blind, pk_i]));
}

// circuits/pi_cred.circom 의 msgHasher(DOMAIN_MODE3_CRED, C, max_height 순서)와
// 일치해야 한다.
export async function credMessage(C, max_height) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED, C, max_height]));
}

// circuits/pi_cred.circom 의 ppidHasher(uid, arid, s_u 순서)와 일치해야 한다.
export async function ppid({ uid, arid, s_u }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, arid, s_u]));
}
