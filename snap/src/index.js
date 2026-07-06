import { panel, text, heading } from '@metamask/snaps-sdk';
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

    case 'verifyIdPAuthToken': {
      const params = request.params ?? {};
      const token = params.idpToken ?? {};
      const verification = params.verification ?? {};
      const accepted = Boolean(verification.success);

      return await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'alert',
          content: panel([
            heading('Wallet Step 12'),
            text(`Origin: **${origin}**`),
            text(`Demo mode: Wallet accepted IdP auth token without cryptographic verification: **${accepted ? 'PASS' : 'FAIL'}**`),
            text(`sub: **${token.sub ?? 'n/a'}**`),
            text(`auid_i: ${previewHex(String(token.auid_i ?? 'n/a'), 70)}`),
            text(`arid_i: ${previewHex(String(token.arid_i ?? 'n/a'), 70)}`),
            text(`exp: **${token.exp ?? 'n/a'}**`),
            text(`Wallet result: **${verification.message ?? verification.error ?? 'n/a'}**`),
          ]),
        },
      });
    }

    case 'rpAuthResult': {
      const params = request.params ?? {};
      const result = params.result ?? {};
      const success = Boolean(result.success);

      return await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'alert',
          content: panel([
            heading('Wallet Step 15'),
            text(`Origin: **${origin}**`),
            text(`PPID authentication result: **${success ? 'SUCCESS' : 'FAIL'}**`),
            text(`PPID: ${previewHex(String(result.ppid ?? 'n/a'), 70)}`),
            text(`r_i check: **${result.r_i_check ? 'PASS' : 'FAIL'}**`),
            text(`expire time: **${result.checks?.expireOk ? 'PASS' : 'FAIL'}**`),
            text(`auid_i binding: **${result.checks?.auidBindingOk ? 'PASS' : 'FAIL'}**`),
            text(`PPID binding: **${result.checks?.ppidOk ? 'PASS' : 'FAIL'}**`),
            text(`pi_PPID: **${result.checks?.piPpidOk ? 'PASS' : 'FAIL'}**`),
          ]),
        },
      });
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
