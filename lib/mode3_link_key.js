// lib/mode3_link_key.js — zkWrapper 의 "연결 열쇠"(스펙 2026-11-26 identity-multi-login M3, 보안 검토 I-1). 발급 서버(cia.js)와 브라우저 코어가 같이 쓴다.
//
// 로그인 계정을 붙이거나 떼는 요청은 "패스키(salt)를 지금 갖고 있다" 를 보여야 한다. auid 는 그 증거로 약하다 — 바뀌지 않는 값이고 브라우저의 등록 기록과 서버에
// 그대로 있어, 한 번 읽히면 패스키 없이 되풀이해 낼 수 있다. 그래서 salt 에서 서명 키를 유도한다:
//   · 연결 열쇠 = secp256k1 개인키 SHA-256("zkwrapper-link-key-v1|" + salt). 저장하지 않는다 — 패스키로 salt 를 만든 그 자리에서만 생긴다.
//   · 서버는 등록(첫 발급) 때 그 주소(link_key)를 계정에 고정한다. 그 뒤에는 바꾸지 않는다.
//   · 연결 begin·떼기 요청마다 이 열쇠로 그 요청의 내용(begin 은 다음 요청 키의 해시, 떼기는 뗄 uid)과 서버 주소에 서명한다. 서버는 고정한 주소로 확인한다.
// 서명은 요청 내용에 묶여 있어 다른 next·다른 uid·다른 서버에 다시 쓸 수 없다. begin 의 next 는 요청자가 방금 만든 키의 해시라, 옛 서명을 주워도 그 키가 없으면 finish 를 못 한다.
import { ethers } from 'ethers';

const DOMAIN = 'zkwrapper-link-key-v1|';
const PLAIN = /^[^|\u0000-\u001f\u007f]+$/;
const bad = (msg) => Object.assign(new Error(msg), { reason: 'malformed' });

/** salt(10진 문자열 또는 bigint)의 연결 열쇠 — ethers.Wallet. 값은 호출한 자리의 메모리에만 둔다. */
export function linkWalletOf(s_u) {
  const s = BigInt(s_u);
  if (s <= 0n) throw bad('salt');
  return new ethers.Wallet(ethers.sha256(ethers.toUtf8Bytes(DOMAIN + s.toString())));
}
/** 계정에 고정할 주소(체크섬 표기). */
export const linkKeyOf = (s_u) => linkWalletOf(s_u).address;
export const isLinkKey = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);

/** 서명하는 글 — op 'begin' 은 next(16진 64자), 'remove' 는 uid(10진). */
export function linkProofMessage(req, aud) {
  if (typeof aud !== 'string' || !PLAIN.test(aud)) throw bad('aud');
  if (req?.op === 'begin' && typeof req.next === 'string' && /^[0-9a-f]{64}$/.test(req.next)) return ['zkwrapper', 'link-proof', aud, 'begin', req.next].join('|');
  if (req?.op === 'remove' && typeof req.uid === 'string' && /^[0-9]{1,80}$/.test(req.uid)) return ['zkwrapper', 'link-proof', aud, 'remove', req.uid].join('|');
  throw bad('link proof request');
}
/** 브라우저: salt 로 그 요청에 서명한다(EIP-191 personal_sign 형식의 65바이트 16진). */
export async function signLinkProof(s_u, req, aud) { return linkWalletOf(s_u).signMessage(linkProofMessage(req, aud)); }
/** 서버: 그 서명이 계정에 고정한 주소의 것인가. 형식이 틀리면 false(던지지 않는다). */
export function linkProofOk(address, req, aud, sig) {
  try { return isLinkKey(address) && typeof sig === 'string' && ethers.verifyMessage(linkProofMessage(req, aud), sig).toLowerCase() === address.toLowerCase(); }
  catch { return false; }
}
