// 서브트리 삽입 전이의 Groth16 증명 생성 (설계 문서 13.2절).
//
// RevocationRegistryV4는 새 root를 받지 않고 **현재 root에서 유도한다.** 그러려면
// "이 서브트리가 oldSubRoot에서 newSubRoot로 간 것이 정당한 삽입들 때문"임을 증명해야
// 한다. 그 증명을 여기서 만든다.
//
// 회로: circuits/pi_ins_sess.circom (깊이 8, K=4) / circuits/pi_ins_acct.circom (깊이 10, K=4)
// 공개 신호는 [oldRoot, newRoot] 둘뿐이다.
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { SESSION_SUBTREE_DEPTH, ACCOUNT_SUBTREE_DEPTH, rootToBytes32 } from './imt_v3.js';

/** 회로 한 건이 담을 수 있는 삽입 건수. 회로 파일의 K와 같아야 한다. */
export const INSERT_BATCH_K = 4;

const CIRCUITS = {
  session: {
    depth: SESSION_SUBTREE_DEPTH,
    wasm: 'build/mode2_v4/pi_ins_sess_js/pi_ins_sess.wasm',
    zkey: 'build/mode2_v4/pi_ins_sess_final.zkey',
    vkey: 'build/mode2_v4/pi_ins_sess_vkey.json',
  },
  account: {
    depth: ACCOUNT_SUBTREE_DEPTH,
    wasm: 'build/mode2_v4/pi_ins_acct_js/pi_ins_acct.wasm',
    zkey: 'build/mode2_v4/pi_ins_acct_final.zkey',
    vkey: 'build/mode2_v4/pi_ins_acct_vkey.json',
  },
};

export function circuitFor(layer) {
  const c = CIRCUITS[layer];
  if (!c) throw new Error(`unknown layer ${layer} (expected 'session' or 'account')`);
  return c;
}

/**
 * 전이 기록 몇 건을 회로 입력 하나로 묶는다.
 *
 * 기록은 **같은 서브트리에서 순차로** 뽑은 것이어야 한다 — 앞 기록의 newRoot가 뒤 기록의
 * oldRoot여야 회로의 root 사슬이 이어진다. 여기서 그 조건을 먼저 확인한다. 어긋난 채로
 * 증명을 만들면 witness 생성이 실패해 원인을 알기 어려운 에러가 난다.
 */
export function buildInsertInput(transcripts, depth, K = INSERT_BATCH_K) {
  if (transcripts.length === 0) throw new Error('at least one transcript is required');
  if (transcripts.length > K) {
    throw new Error(`${transcripts.length} transcripts exceed the circuit batch size K=${K}`);
  }
  for (let i = 1; i < transcripts.length; i++) {
    if (transcripts[i].oldRoot !== transcripts[i - 1].newRoot) {
      throw new Error(
        `transcript ${i} starts at ${transcripts[i].oldRoot} but ${i - 1} ended at ` +
          `${transcripts[i - 1].newRoot} — they must come from the same subtree, in order`,
      );
    }
  }

  const zeros = (n) => new Array(n).fill('0');
  const input = {
    oldRoot: transcripts[0].oldRoot,
    newRoot: transcripts[transcripts.length - 1].newRoot,
    active: [],
    newValue: [],
    lowValue: [],
    lowNextIndex: [],
    lowNextValue: [],
    lowPathIndices: [],
    lowSiblings: [],
    newIndex: [],
    newPathIndices: [],
    newSiblings: [],
  };

  for (let i = 0; i < K; i++) {
    const t = transcripts[i];
    input.active.push(t ? '1' : '0');
    input.newValue.push(t ? t.newValue : '0');
    input.lowValue.push(t ? t.lowValue : '0');
    input.lowNextIndex.push(t ? t.lowNextIndex : '0');
    input.lowNextValue.push(t ? t.lowNextValue : '0');
    input.lowPathIndices.push(t ? t.lowPathIndices : zeros(depth));
    input.lowSiblings.push(t ? t.lowSiblings : zeros(depth));
    input.newIndex.push(t ? t.newIndex : '0');
    input.newPathIndices.push(t ? t.newPathIndices : zeros(depth));
    input.newSiblings.push(t ? t.newSiblings : zeros(depth));
  }
  return input;
}

/** Groth16 증명을 컨트랙트 calldata 모양으로. snarkjs의 B는 좌표 순서가 뒤집혀 있다. */
export function toSolidityCalldata(proof) {
  return {
    a: [proof.pi_a[0], proof.pi_a[1]],
    b: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    c: [proof.pi_c[0], proof.pi_c[1]],
  };
}

/**
 * 한 서브트리의 삽입 전이를 증명한다.
 *
 * @param layer 'session' | 'account'
 * @param transcripts insertWithTranscript()가 돌려준 기록들 (같은 서브트리, 순서대로)
 * @returns { oldRoot, newRoot, proof, calldata, publicSignals }
 */
export async function proveInsertTransition(layer, transcripts) {
  const c = circuitFor(layer);
  const input = buildInsertInput(transcripts, c.depth);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, c.wasm, c.zkey);
  return {
    oldRoot: input.oldRoot,
    newRoot: input.newRoot,
    proof,
    calldata: toSolidityCalldata(proof),
    publicSignals,
  };
}

/** 만든 증명을 로컬에서 다시 검증한다. 온체인에 보내기 전 자기 점검용. */
export async function verifyInsertTransition(layer, proof, publicSignals) {
  const c = circuitFor(layer);
  const vkey = JSON.parse(fs.readFileSync(c.vkey, 'utf8'));
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

/** RevocationRegistryV4.Kind — 컨트랙트의 enum 순서와 같아야 한다. */
export const KIND = { insert: 0, sessionReset: 1, accountRebaseline: 2 };

/** 증명이 필요 없는 전이의 자리 채움. */
const NO_PROOF = { a: [0, 0], b: [[0, 0], [0, 0]], c: [0, 0] };

/**
 * IdP가 준 전이 서술자에 증명을 붙여 컨트랙트 calldata로 바꾼다.
 *
 * **순서를 바꾸면 안 된다.** 컨트랙트가 순차로 접으므로 i번째 전이의 형제 경로는
 * 0..i-1이 반영된 상태를 전제한다. IdP가 포레스트를 바꾼 순서 그대로 와야 한다
 * (설계 문서 13.2절).
 *
 * 증명 생성은 IdP가 아니라 여기서 한다. 재료가 전부 이미 공개된 트리 내용이고, IdP의
 * 관리자 경로는 직렬화돼 있어 회차마다 수 초를 잡으면 다른 관리 조작까지 막히기 때문이다.
 *
 * @param descriptors /idp/publish/commit 응답의 updates
 * @param onProgress  (i, total, kind) — 증명이 느려 진행 상황을 알리고 싶을 때
 */
export async function buildContractUpdates(descriptors, onProgress) {
  const out = [];
  for (const [i, d] of descriptors.entries()) {
    if (onProgress) onProgress(i + 1, descriptors.length, d.kind);
    const base = {
      kind: KIND[d.kind],
      account: Boolean(d.account),
      shard: d.shard,
      oldSubRoot: rootToBytes32(d.oldSubRoot),
      newSubRoot: rootToBytes32(d.newSubRoot),
      siblings: d.siblings,
    };
    if (base.kind === undefined) throw new Error(`unknown transition kind ${d.kind}`);

    if (d.kind === 'insert') {
      const layer = d.account ? 'account' : 'session';
      const proved = await proveInsertTransition(layer, d.transcripts);
      // 증명이 실제로 이 전이를 말하는지 스스로 확인한다. 어긋난 채로 올리면 온체인에서야
      // revert로 드러나고, 그 회차는 IdP만 앞선 상태로 남는다.
      if (rootToBytes32(proved.oldRoot) !== base.oldSubRoot ||
          rootToBytes32(proved.newRoot) !== base.newSubRoot) {
        throw new Error(
          `proof public signals do not match descriptor ${i} ` +
          `(${proved.oldRoot} -> ${proved.newRoot} vs ${d.oldSubRoot} -> ${d.newSubRoot})`,
        );
      }
      out.push({ ...base, ...proved.calldata });
    } else {
      out.push({ ...base, ...NO_PROOF });
    }
  }
  return out;
}
