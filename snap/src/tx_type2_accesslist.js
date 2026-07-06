// snap/src/tx_type2_accesslist.js
// Utilities to encode a ZKP attachment into EIP-2930/1559/4844 accessList without
// changing the original tx calldata (to/value/data).
//
// Encoding (storageKeys):
//   [0] tag0 = keccak256("ZKP_ATTEST_V1")
//   [1] tag1 = keccak256(pack(chainId, nonce, to, value, keccak256(data)))
//   [2] payloadHash = keccak256(payloadBytes)
//   [3] payloadLen (uint256, bytes32)              // only when mode === 'full'
//   [4..] payloadChunks (bytes32[])                // only when mode === 'full'
//
// Notes:
// - accessList is part of the signed tx payload. Recipients can ignore it; EVM
//   execution doesn't read accessList.
// - mode 'full' can be expensive if payload is large.

import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export const ZKP_VERSION_TAG_DEFAULT = 'ZKP_ATTEST_V1';

// Domain separation for binding tag (tag1)
export const BINDING_DOMAIN_CALL = 'ZKP_BIND_CALL_V1';
export const BINDING_DOMAIN_CREATE = 'ZKP_BIND_CREATE_V1';

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesTo0xHex(u8) {
  return '0x' + bytesToHex(u8);
}

export function hexToU8(hex) {
  if (typeof hex !== 'string' || !hex.startsWith('0x')) {
    throw new Error('hex must be 0x-prefixed string');
  }
  return hexToBytes(hex.slice(2));
}

export function keccak256Bytes(u8) {
  return keccak_256(u8);
}

export function keccak256Hex(hex0x) {
  return bytesTo0xHex(keccak256Bytes(hexToU8(hex0x)));
}

export function keccak256Utf8(str) {
  return bytesTo0xHex(keccak256Bytes(utf8ToBytes(str)));
}

export function ensure0x(hex) {
  if (!hex) return '0x';
  return hex.startsWith('0x') ? hex : '0x' + hex;
}


export function toHexQtyAny(v, name = 'value') {
  if (v == null) throw new Error(`${name} is required`);

  if (typeof v === 'string') {
    // already hex
    if (v.startsWith('0x') || v.startsWith('0X')) {
      const s = '0x' + strip0x(v).toLowerCase();
      return s === '0x' ? '0x0' : s;
    }
    // decimal string
    if (/^[0-9]+$/.test(v.trim())) return bigIntToHexQty(BigInt(v.trim()));
    throw new Error(`${name} must be a hex-qty or decimal string`);
  }

  if (typeof v === 'number') {
    if (!Number.isFinite(v) || v < 0) throw new Error(`${name} must be a non-negative finite number`);
    return bigIntToHexQty(BigInt(v));
  }

  if (typeof v === 'bigint') {
    if (v < 0n) throw new Error(`${name} must be non-negative`);
    return bigIntToHexQty(v);
  }

  throw new Error(`${name} has unsupported type`);
}





export function strip0x(hex) {
  return hex.startsWith('0x') ? hex.slice(2) : hex;
}

export function isAddressLike(addr) {
  return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

export function isBytes32Hex(h) {
  return typeof h === 'string' && /^0x[0-9a-fA-F]{64}$/.test(h);
}

export function isType3LikeTx(tx) {
  const t = tx?.type;
  return t === '0x3' || t === 3 || t === '3' || tx?.blobVersionedHashes != null || tx?.maxFeePerBlobGas != null;
}

export function assertBlobFields(baseTx) {
  const hashes = baseTx?.blobVersionedHashes;
  if (!Array.isArray(hashes) || hashes.length === 0) {
    throw new Error('Type-3 tx requires non-empty baseTx.blobVersionedHashes');
  }
  for (const h of hashes) {
    if (!isBytes32Hex(h)) {
      throw new Error('Type-3 tx requires blobVersionedHashes entries as 0x + 64-hex (bytes32)');
    }
  }
  if (baseTx?.maxFeePerBlobGas == null) {
    throw new Error('Type-3 tx requires baseTx.maxFeePerBlobGas');
  }
}

export function buildType3TxWithZkp({
  baseTx,
  txContext,
  payloadBytes,
  attachMode = 'full',
  versionTag = ZKP_VERSION_TAG_DEFAULT,
  marginGas = 20_000n,
}) {
  if (!baseTx || typeof baseTx !== 'object') throw new Error('baseTx must be object');
  if (!txContext || typeof txContext !== 'object') throw new Error('txContext must be object');

  assertBlobFields(baseTx);

  const isCreate = baseTx.to == null || baseTx.to === '';
  const to = isCreate ? undefined : baseTx.to;
  if (!isCreate && !isAddressLike(to)) {
    throw new Error('baseTx.to must be 0x address');
  }

  const chainIdHex = toHexQtyAny(txContext.chainId, 'txContext.chainId');
  const nonceHex = toHexQtyAny(txContext.nonce, 'txContext.nonce');

  const valueHex = ensure0x(baseTx.value || '0x0');
  const dataHex = ensure0x(baseTx.data || '0x');
  if (isCreate && dataHex.toLowerCase() === '0x') {
    throw new Error('contract creation requires non-empty initcode in baseTx.data');
  }

  const baseGasHex = ensure0x(baseTx.gas || baseTx.gasLimit);
  if (!baseGasHex || baseGasHex === '0x') throw new Error('baseTx.gas (or gasLimit) is required');

  const entry = buildZkpAccessListEntry({
    chainIdHex,
    nonceHex,
    to,
    valueHex,
    dataHex,
    payloadBytes,
    versionTag,
    mode: attachMode,
  });

  const merged = mergeAccessList(baseTx.accessList || [], entry);
  const deltaGas = calcAccessListDeltaGas(merged);

  const baseGas = hexQtyToBigInt(baseGasHex);
  const gas = baseGas + deltaGas + BigInt(marginGas);

  const maxFeePerBlobGasHex = toHexQtyAny(baseTx.maxFeePerBlobGas, 'baseTx.maxFeePerBlobGas');

  const tx = {
    type: '0x3',
    chainId: chainIdHex,
    nonce: nonceHex,
    value: valueHex,
    data: dataHex,
    gas: bigIntToHexQty(gas),
    accessList: merged.accessList,
    maxFeePerBlobGas: maxFeePerBlobGasHex,
    blobVersionedHashes: baseTx.blobVersionedHashes,
  };
  if (!isCreate) tx.to = to;

  if (baseTx.maxFeePerGas != null) tx.maxFeePerGas = ensure0x(baseTx.maxFeePerGas);
  if (baseTx.maxPriorityFeePerGas != null) tx.maxPriorityFeePerGas = ensure0x(baseTx.maxPriorityFeePerBlobGas ?? baseTx.maxPriorityFeePerGas);

  return { tx, entry, merged, deltaGas: bigIntToHexQty(deltaGas), finalGas: tx.gas };
}

export function buildTxWithZkp(args) {
  if (isType3LikeTx(args?.baseTx)) return buildType3TxWithZkp(args);
  return buildType2TxWithZkp(args);
}

export function hexQtyToBigInt(q) {
  if (typeof q === 'bigint') return q;
  if (typeof q === 'number') return BigInt(q);
  if (typeof q !== 'string') throw new Error('quantity must be hex string');
  return BigInt(q);
}

export function bigIntToHexQty(x) {
  const b = typeof x === 'bigint' ? x : BigInt(x);
  if (b === 0n) return '0x0';
  return '0x' + b.toString(16);
}

export function bigIntToBytes32(x) {
  const b = typeof x === 'bigint' ? x : BigInt(x);
  if (b < 0n) throw new Error('uint256 must be non-negative');
  let hex = b.toString(16);
  if (hex.length > 64) throw new Error('uint256 too large');
  hex = hex.padStart(64, '0');
  return hexToU8('0x' + hex);
}

export function leftPadTo32(u8) {
  if (u8.length > 32) throw new Error('chunk longer than 32 bytes');
  const out = new Uint8Array(32);
  out.set(u8, 0);
  return out;
}

export function chunkTo32Bytes(u8) {
  const out = [];
  for (let i = 0; i < u8.length; i += 32) {
    const chunk = u8.slice(i, i + 32);
    const padded = new Uint8Array(32);
    padded.set(chunk);
    out.push(padded);
  }
  if (out.length === 0) out.push(new Uint8Array(32));
  return out;
}

export function concatBytes(parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Solidity packed encoding for:
 *   (uint256 chainId, uint256 nonce, address to, uint256 value, bytes32 dataHash)
 */
export function packBinding({ chainId, nonce, to, value, dataHash32 }) {
  if (!isAddressLike(to)) throw new Error('to must be 0x + 40-hex address');
  const toBytes = hexToU8(to);
  if (toBytes.length !== 20) throw new Error('invalid address bytes');

  const parts = [
    bigIntToBytes32(chainId),
    bigIntToBytes32(nonce),
    toBytes, // 20 bytes (packed)
    bigIntToBytes32(value),
    hexToU8(dataHash32), // 32 bytes
  ];
  return concatBytes(parts);
}

/**
 * Solidity packed encoding for contract creation binding:
 *   (uint256 chainId, uint256 nonce, uint256 value, bytes32 initCodeHash)
 */
export function packBindingCreate({ chainId, nonce, value, initCodeHash32 }) {
  const parts = [
    bigIntToBytes32(chainId),
    bigIntToBytes32(nonce),
    bigIntToBytes32(value),
    hexToU8(initCodeHash32), // 32 bytes
  ];
  return concatBytes(parts);
}

export function stableStringify(obj) {
  // Minimal stable stringify for deterministic payload bytes.
  // - Sort object keys recursively.
  // - Keep arrays in order.
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map((v) => stableStringify(v)).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const items = keys.map((k) => {
    return JSON.stringify(k) + ':' + stableStringify(obj[k]);
  });
  return '{' + items.join(',') + '}';
}

export function buildZkpAccessListEntry({
  chainIdHex,
  nonceHex,
  to,
  valueHex,
  dataHex,
  payloadBytes,
  versionTag = ZKP_VERSION_TAG_DEFAULT,
  mode = 'full',
}) {
  const isCreate = to == null || to === '';
  if (!isCreate && !isAddressLike(to)) {
    throw new Error('buildZkpAccessListEntry: invalid `to`');
  }

  const chainId = hexQtyToBigInt(chainIdHex);
  const nonce = hexQtyToBigInt(nonceHex);
  const value = valueHex ? hexQtyToBigInt(valueHex) : 0n;
  const data = ensure0x(dataHex || '0x');

  const tag0 = keccak256Utf8(versionTag); // bytes32 hex

  const dataHash = bytesTo0xHex(keccak256Bytes(hexToU8(data)));
  let packed;
  let domain;
  if (isCreate) {
    // Contract creation: bind to initcode hash instead of `to`
    packed = packBindingCreate({
      chainId,
      nonce,
      value,
      initCodeHash32: dataHash,
    });
    domain = BINDING_DOMAIN_CREATE;
  } else {
    packed = packBinding({
      chainId,
      nonce,
      to,
      value,
      dataHash32: dataHash,
    });
    domain = BINDING_DOMAIN_CALL;
  }

  // tag1 = keccak256( domain || packedBinding )
  const tag1 = bytesTo0xHex(keccak256Bytes(concatBytes([utf8ToBytes(domain), packed])));

  const payloadHash = bytesTo0xHex(keccak256Bytes(payloadBytes));

  const storageKeys = [tag0, tag1, payloadHash];

  if (mode === 'full') {
    const lenKey = bytesTo0xHex(bigIntToBytes32(BigInt(payloadBytes.length)));
    storageKeys.push(lenKey);

    for (const c of chunkTo32Bytes(payloadBytes)) {
      storageKeys.push(bytesTo0xHex(c));
    }
  }

  // Derive a deterministic carrier address from tag0 (last 20 bytes)
  const carrier = '0x' + strip0x(tag0).slice(24);

  return {
    address: carrier,
    storageKeys,
    tag0,
    tag1,
    payloadHash,
  };
}

export function mergeAccessList(existing, entry) {
  const list = Array.isArray(existing) ? existing.map((e) => ({
    address: e.address,
    storageKeys: Array.isArray(e.storageKeys) ? [...e.storageKeys] : [],
  })) : [];

  let addressAdded = 0;
  let keysAdded = 0;

  const idx = list.findIndex((e) => (e.address || '').toLowerCase() === entry.address.toLowerCase());
  if (idx === -1) {
    list.push({ address: entry.address, storageKeys: [...entry.storageKeys] });
    addressAdded = 1;
    keysAdded = entry.storageKeys.length;
  } else {
    const existingSet = new Set(list[idx].storageKeys.map((k) => k.toLowerCase()));
    const appended = [];
    for (const k of entry.storageKeys) {
      const kk = k.toLowerCase();
      if (!existingSet.has(kk)) appended.push(k);
    }
    list[idx].storageKeys.push(...appended);
    keysAdded = appended.length;
  }

  return { accessList: list, addressAdded, keysAdded };
}

export function calcAccessListDeltaGas({ addressAdded, keysAdded }) {
  // EIP-2930 costs: 2400 per address, 1900 per storage key.
  // EIP-1559 (Type 2) and EIP-4844 (Type 3) include accessList with same semantics.
  // We only need the delta for additional entries we introduce.
  return 2400n * BigInt(addressAdded) + 1900n * BigInt(keysAdded);
}

export function buildType2TxWithZkp({
  baseTx,
  txContext,
  payloadBytes,
  attachMode = 'full',
  versionTag = ZKP_VERSION_TAG_DEFAULT,
  marginGas = 20_000n,
}) {
  if (!baseTx || typeof baseTx !== 'object') throw new Error('baseTx must be object');
  if (!txContext || typeof txContext !== 'object') throw new Error('txContext must be object');

  const isCreate = baseTx.to == null || baseTx.to === '';
  const to = isCreate ? undefined : baseTx.to;
  if (!isCreate && !isAddressLike(to)) {
    throw new Error('baseTx.to must be 0x address');
  }

  //const chainIdHex = ensure0x(txContext.chainId);
  //const nonceHex = ensure0x(txContext.nonce);
  const chainIdHex = toHexQtyAny(txContext.chainId, 'txContext.chainId');
  const nonceHex = toHexQtyAny(txContext.nonce, 'txContext.nonce');


  const valueHex = ensure0x(baseTx.value || '0x0');
  const dataHex = ensure0x(baseTx.data || '0x');
  if (isCreate && dataHex.toLowerCase() === '0x') {
    throw new Error('contract creation requires non-empty initcode in baseTx.data');
  }
  const baseGasHex = ensure0x(baseTx.gas || baseTx.gasLimit);
  if (!baseGasHex || baseGasHex === '0x') throw new Error('baseTx.gas (or gasLimit) is required');

  const entry = buildZkpAccessListEntry({
    chainIdHex,
    nonceHex,
    to,
    valueHex,
    dataHex,
    payloadBytes,
    versionTag,
    mode: attachMode,
  });

  const merged = mergeAccessList(baseTx.accessList || [], entry);
  const deltaGas = calcAccessListDeltaGas(merged);

  const baseGas = hexQtyToBigInt(baseGasHex);
  const gas = baseGas + deltaGas + BigInt(marginGas);

  const tx = {
    type: '0x2',
    chainId: chainIdHex,
    nonce: nonceHex,
    value: valueHex,
    data: dataHex,
    gas: bigIntToHexQty(gas),
    accessList: merged.accessList,
    // fees are intentionally omitted; MetaMask can fill them.
  };
  if (!isCreate) {
    tx.to = to;
  }

  return {
    tx,
    entry,
    merged,
    deltaGas: bigIntToHexQty(deltaGas),
    finalGas: tx.gas,
  };
}
