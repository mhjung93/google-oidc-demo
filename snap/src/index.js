import { panel, text, heading } from '@metamask/snaps-sdk';
import * as mcl from 'mcl-wasm';
import {
  buildTxWithZkp,
  stableStringify,
  utf8ToBytes,
  ZKP_VERSION_TAG_DEFAULT,
  toHexQtyAny,
} from './tx_type2_accesslist.js';

function previewHex(hex0x, maxChars = 70) {
  if (typeof hex0x !== 'string') return '';
  return hex0x.length > maxChars ? `${hex0x.slice(0, maxChars)}...` : hex0x;
}

function tokenMessages(token) {
  return [
    'IDP_TOKEN',
    String(token.arid_i),
    String(token.auid_i),
    String(token.r_token),
    String(token.max_height),
    String(token.chain_id),
  ];
}

function assertTokenMatchesWalletSubmission(token, walletSubmission, business) {
  const checks = {
    aridOk: String(token.arid_i) === String(walletSubmission?.arid_i ?? business?.arid_i),
    auidOk: String(token.auid_i) === String(walletSubmission?.auid_i ?? business?.auid_i),
    tokenNonceOk: String(token.r_token) === String(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce),
    maxHeightOk: String(token.max_height) === String(business?.maxHeight ?? business?.max_height),
    chainIdOk: String(token.chain_id) === String(business?.chain_id ?? business?.chainId),
  };

  const success = checks.aridOk && checks.auidOk && checks.tokenNonceOk && checks.maxHeightOk && checks.chainIdOk;
  return { success, checks };
}

function randomHex32() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

// custom_idp.js의 initPS()/psSign()이 사용하는 것과 동일한 curve.
let mclReady = null;
function ensureMcl() {
  if (!mclReady) mclReady = mcl.init(mcl.BN_SNARK1);
  return mclReady;
}

function hashToFr(str) {
  const fr = new mcl.Fr();
  fr.setHashOf(str);
  return fr;
}

// custom_idp.js의 psSign() / server.js의 verifyPS_Hybrid()와 동일한 PS 서명 검증식.
// e(sigma1, X * prod(Yi^mi)) == e(sigma2, g2)
function verifyPS(messages, sigma, psPublicKeys) {
  const s1 = new mcl.G1();
  s1.setStr(sigma.sigma1, 16);
  const s2 = new mcl.G1();
  s2.setStr(sigma.sigma2, 16);

  if (s1.isZero()) return false;

  const g2 = new mcl.G2();
  g2.setStr(psPublicKeys.g2, 16);
  const X = new mcl.G2();
  X.setStr(psPublicKeys.X, 16);

  let PK_total = new mcl.G2();
  PK_total = mcl.add(X, PK_total);
  for (let i = 0; i < messages.length; i++) {
    const Yi = new mcl.G2();
    Yi.setStr(psPublicKeys.Y[i], 16);
    const mi = hashToFr(messages[i]);
    PK_total = mcl.add(PK_total, mcl.mul(Yi, mi));
  }

  const lhs = mcl.pairing(s1, PK_total);
  const rhs = mcl.pairing(s2, g2);
  return lhs.isEqual(rhs);
}

export const onRpcRequest = async ({ origin, request }) => {
  switch (request.method) {
    case 'hello': {
      // Return boolean (confirmed/cancelled)
      return await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            text(`Hello, **${origin}**!`),
            text('This is a demo snap for user-consent traceability.'),
          ]),
        },
      });
    }

    case 'confirmLogin': {
      const confirmed = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Wallet Login Approval'),
            text(`Origin: **${origin}**`),
            text('A PairCT-compatible identity provider login is about to start in your system browser.'),
            text('Do you want to proceed?'),
          ]),
        },
      });
      return { approved: Boolean(confirmed) };
    }

    case 'walletProcessSummary': {
      const params = request.params ?? {};
      const lines = Array.isArray(params.lines) ? params.lines : [];
      const content = [
        heading('Wallet Processing'),
        text(`Origin: **${origin}**`),
        ...lines.slice(0, 12).map((line) => text(String(line))),
      ];

      return await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'alert',
          content: panel(content),
        },
      });
    }

    case 'getOrCreateWalletSalt': {
      const state = (await snap.request({
        method: 'snap_manageState',
        params: { operation: 'get' },
      })) ?? {};

      if (!state.mode2WalletSalt) {
        state.mode2WalletSalt = randomHex32();
        await snap.request({
          method: 'snap_manageState',
          params: { operation: 'update', newState: state },
        });
      }

      return { salt: state.mode2WalletSalt };
    }

    case 'verifyIdPAuthToken': {
      const params = request.params ?? {};
      const token = params.idpToken ?? {};
      const psPublicKeys = params.psPublicKeys ?? {};
      const walletSubmission = params.walletSubmission ?? {};
      const business = params.business ?? {};

      let accepted = false;
      let binding = { success: true, checks: { ridOk: true, aridOk: true, auidOk: true, tokenNonceOk: true, maxHeightOk: true, chainIdOk: true } };
      let message;
      const verifyStart = Date.now();
      let durationMs = null;
      try {
        await ensureMcl();
        accepted = verifyPS(tokenMessages(token), token.signature ?? {}, psPublicKeys);
        if (params.walletSubmission || params.business) {
          binding = assertTokenMatchesWalletSubmission(token, walletSubmission, business);
        }
        accepted = accepted && binding.success;
        message = accepted ? 'PS signature and Wallet bindings verified' : 'PS signature or Wallet binding verification failed';
      } catch (err) {
        message = `Verification error: ${err.message}`;
      } finally {
        durationMs = Date.now() - verifyStart;
      }

      await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'alert',
          content: panel([
            heading('Wallet Step 12'),
            text(`Origin: **${origin}**`),
            text(`PS signature verification: **${accepted ? 'PASS' : 'FAIL'}**`),
            text(`auid_i: ${previewHex(String(token.auid_i ?? 'n/a'), 70)}`),
            text(`arid_i: ${previewHex(String(token.arid_i ?? 'n/a'), 70)}`),
            text(`r_token: ${previewHex(String(token.r_token ?? 'n/a'), 70)}`),
            text(`max_height: **${token.max_height ?? 'n/a'}**`),
            text(`chain_id: **${token.chain_id ?? 'n/a'}**`),
            text('_binding checks below confirm each field matches what this wallet itself submitted in Step 8 — a FAIL means the token was swapped or tampered with._'),
            text(`r_token binding: **${binding.checks.tokenNonceOk ? 'PASS' : 'FAIL'}**`),
            text(`max_height binding: **${binding.checks.maxHeightOk ? 'PASS' : 'FAIL'}**`),
            text(`chain_id binding: **${binding.checks.chainIdOk ? 'PASS' : 'FAIL'}**`),
            text(`arid_i binding: **${binding.checks.aridOk ? 'PASS' : 'FAIL'}**`),
            text(`auid_i binding: **${binding.checks.auidOk ? 'PASS' : 'FAIL'}**`),
            text(`Wallet result: **${message}**`),
          ]),
        },
      });

      return { success: accepted, message, checks: binding.checks, durationMs };
    }

    case 'rpAuthResult': {
      const processingStart = Date.now();
      const params = request.params ?? {};
      const result = params.result ?? {};
      const success = Boolean(result.success);
      const durationMs = Date.now() - processingStart;

      await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'alert',
          content: panel([
            heading('Wallet Step 15'),
            text(`Origin: **${origin}**`),
            text(`PPID authentication result: **${success ? 'SUCCESS' : 'FAIL'}**`),
            text(`PPID: ${previewHex(String(result.ppid ?? 'n/a'), 70)}`),
            text('_checks below were run by the RP frontend: is this the same session (r_i), does this PPID really derive the RP-issued auid_i, does the PPID belong to the RP registered rid, and is the pi_PPID ZK proof itself valid._'),
            text(`r_i check: **${result.r_i_check ? 'PASS' : 'FAIL'}**`),
            text(`RP backend token/audience: **${result.checks?.rpBackendOk ? 'PASS' : 'FAIL'}**`),
            text(`max_height: **${(result.checks?.heightOk ?? result.checks?.expireOk) ? 'PASS' : 'FAIL'}**`),
            text(`auid_i binding: **${result.checks?.auidBindingOk ? 'PASS' : 'FAIL'}**`),
            text(`PPID binding: **${result.checks?.ppidOk ? 'PASS' : 'FAIL'}**`),
            text(`pi_PPID: **${result.checks?.piPpidOk ? 'PASS' : 'FAIL'}**`),
            text(`Step 8 duration: **${result.step8DurationMs != null ? Math.round(result.step8DurationMs) + ' ms' : 'n/a'}**`),
            text(`Step 12 duration: **${result.step12DurationMs != null ? Math.round(result.step12DurationMs) + ' ms' : 'n/a'}**`),
          ]),
        },
      });

      return { success, durationMs };
    }

    case 'zkp':
    case 'sendZkProof': {
      const params = request.params ?? {};

      const proof = params.proof;
      const publicSignals = params.publicSignals;
      const ciphertext = params.ciphertext ?? 'ciphertext';

      // Compatibility layer for older client.js that doesn't use baseTx/txContext
      let baseTx = params.baseTx;
      let txContext = params.txContext;

      if (!baseTx && (params.to || params.data)) {
        baseTx = {
          to: params.to,
          data: params.data,
          value: params.value ?? '0x0',
          gas: params.gas ?? params.gasLimit ?? '0x50000', // Default if missing
        };
      }

      if (!txContext && (params.chainId || params.nonce)) {
        txContext = {
          chainId: params.chainId,
          nonce: params.nonce
        };
      }

      const attachMode = params.attachMode ?? 'full'; // 'full' | 'hash-only'
      const versionTag = params.versionTag ?? ZKP_VERSION_TAG_DEFAULT;
      const marginGas = params.marginGas != null ? BigInt(params.marginGas) : 20000n;

      if (!proof || typeof proof !== 'object') {
        throw new Error('sendZkProof/zkp: missing/invalid `proof`');
      }
      if (!baseTx || typeof baseTx !== 'object') {
        throw new Error('sendZkProof/zkp: missing/invalid `baseTx` (or to/data params)');
      }

      // txContext가 없으면 에러를 던지기 전에 디폴트값 부여 시도 (가급적 클라이언트에서 주는 것이 좋음)
      if (!txContext || txContext.chainId == null || txContext.nonce == null) {
        throw new Error('sendZkProof/zkp: txContext (chainId and nonce) is required. Please update client.js to provide these.');
      }
      const isCreate = baseTx.to == null || baseTx.to === '';

      // Contract creation tx: `to` is omitted and `data` carries initcode.
      if (!isCreate) {
        if (typeof baseTx.to !== 'string') {
          throw new Error('sendZkProof: baseTx.to must be a 0x address string');
        }
      } else {
        // For CREATE, require initcode in `data`
        if (typeof baseTx.data !== 'string' || baseTx.data.toLowerCase() === '0x') {
          throw new Error('sendZkProof: contract creation requires non-empty baseTx.data (initcode)');
        }
      }
      if (baseTx.data != null && typeof baseTx.data !== 'string') {
        throw new Error('sendZkProof: baseTx.data must be a hex string');
      }
      if (baseTx.gas == null && baseTx.gasLimit == null) {
        throw new Error('sendZkProof: baseTx.gas (or gasLimit) is required');
      }
      //if (!txContext.chainId || !txContext.nonce) {
      //  throw new Error('sendZkProof: txContext.chainId and txContext.nonce are required');
      //}
      // nonce는 0이 될 수 있으니 truthy 체크 금지
      if (txContext.chainId == null || txContext.nonce == null) {
        throw new Error('sendZkProof: txContext.chainId and txContext.nonce are required');
      }
       
      // ✅ 항상 hex quantity로 정규화
      const chainIdHex = toHexQtyAny(txContext.chainId, 'txContext.chainId');
      const nonceHex = toHexQtyAny(txContext.nonce, 'txContext.nonce');
  

      // Build payload bytes to be attached into accessList.
      // NOTE: This payload is NOT executed by the EVM (accessList is not readable in-contract).
      // It is part of the signed tx so recipients can ignore it safely.
      const payloadStr = stableStringify({ proof, publicSignals, ciphertext });
      const payloadBytes = utf8ToBytes(payloadStr);

      const built = buildTxWithZkp({
        baseTx,
        //txContext,
        txContext: { chainId: chainIdHex, nonce: nonceHex },
        payloadBytes,
        attachMode,
        versionTag,
        marginGas,
      });

      const carrierKeys = built.entry.storageKeys.length;
      const accessListAddresses = built.merged.accessList.length;

      const confirmed = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading(`Send Tx (type ${built.tx.type}) with ZKP (accessList attachment)`),
            text(`Origin: **${origin}**`),
            text(`To: **${built.tx.to ?? '<contract creation>'}**`),
            text(`Value: **${built.tx.value}**`),
            text(`Data (unchanged, preview): ${previewHex(built.tx.data)}`),
            text(`Attach mode: **${attachMode}**`),
            text(`accessList addresses: **${accessListAddresses}**`),
            text(`carrier storageKeys: **${carrierKeys}**`),
            text(`extra intrinsic gas (delta): **${built.deltaGas}**`),
            text(`gas (final): **${built.finalGas}**`),
            text('ZKP payload is attached in accessList and will not be validated on-chain.'),
          ]),
        },
      });

      if (!confirmed) {
        return { ok: false, reason: 'User rejected' };
      }

      // ✅ dApp will call eth_sendTransaction
      return {
        ok: true,
        tx: built.tx,
        attachment: {
          mode: attachMode,
          carrier: built.entry.address,
          tag0: built.entry.tag0,
          tag1: built.entry.tag1,
          payloadHash: built.entry.payloadHash,
          deltaGas: built.deltaGas,
          finalGas: built.tx.gas, // <-- THIS WAS OLD LINE
          accessListAddresses,
          carrierKeys,
        },
      };
    }

    default:
      throw new Error('Method not found.');
  }
};
