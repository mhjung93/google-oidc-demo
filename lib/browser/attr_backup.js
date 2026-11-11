// lib/browser/attr_backup.js — 속성 도구(mode3/attr.html) 기록의 암호화 백업(2026-11-11, 사용자 결정: 자동 백업·백업 비밀번호, 스펙 D20).
//   백업 비밀번호 → secret_box.js 의 PBKDF2(SHA-256, 310,000회) → AES-GCM. 파일에는 형식 표시·kdf·암호문만 남는다(uid·s_u·속성·blind 평문 없음).
//   키는 추출 불가 CryptoKey 라 페이지가 IndexedDB 에 두고 자동 저장에 다시 쓴다 — 파일만 가진 사람은 비밀번호 없이 열 수 없다.
import { KDF_ITERATIONS, randomSaltHex, deriveKey, encryptJson, decryptJson } from './secret_box.js';

export const BACKUP_FORMAT = 'zkd-attr-backup';
export const BACKUP_MIN_PASSWORD = 8;
const fail = (reason, msg = reason) => Object.assign(new Error(msg), { reason });

/** 비밀번호로 백업 키를 만든다. salt 를 주면 그 값으로(복원·검증), 없으면 새로 뽑는다. → { key, kdf: { salt, iterations } } */
export async function backupKey(password, salt = randomSaltHex(), iterations = KDF_ITERATIONS) {
  if (typeof password !== 'string' || password.length < BACKUP_MIN_PASSWORD) throw fail('bad_backup_password', `백업 비밀번호는 ${BACKUP_MIN_PASSWORD}자 이상`);
  return { key: await deriveKey(password, salt, iterations), kdf: { salt, iterations } };
}
export const isSealedBackup = (o) => Boolean(o && typeof o === 'object' && o.format === BACKUP_FORMAT);
export async function sealBackup(key, kdf, rec) {
  return { format: BACKUP_FORMAT, version: 1, kdf: { salt: kdf.salt, iterations: kdf.iterations }, box: await encryptJson(key, rec), savedAt: new Date().toISOString() };
}
/** 봉인 백업을 비밀번호로 연다 — 형식이 다르면 bad_backup, 비밀번호가 틀리거나 손상됐으면 bad_password. */
export async function openBackup(password, sealed) {
  if (!isSealedBackup(sealed) || sealed.version !== 1 || !sealed.kdf || !/^[0-9a-f]{32}$/.test(sealed.kdf.salt ?? '') || !Number.isInteger(sealed.kdf.iterations)) throw fail('bad_backup', '백업 형식이 다릅니다');
  const key = await deriveKey(String(password ?? '') || ' ', sealed.kdf.salt, sealed.kdf.iterations);
  return decryptJson(key, sealed.box);
}
