// lib/mode3_rp_custody.js — 서비스가 보관하는 계정의 체인 주소(스펙 2026-11-25-mode3-rp-custody-address). RP(mode3_rp.js)만 쓴다.
// 서비스마다 무작위 시드 하나(파일, 0600)에서 계정 id 로 키를 유도한다 — 계정별 키는 저장하지 않는다. 시드 파일 하나가 그 서비스 보관 계정 전부의 키다.
// 시드·개인 키는 로그·응답·오류 문구에 싣지 않는다: 파서·파일 오류를 그대로 내지 않고 고정 문구로 바꾼다.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { HDNodeWallet } from 'ethers';

const DOMAIN = 'zkd-rp-custody-v1|';
const FINGERPRINT_DOMAIN = 'zkd-rp-custody-fingerprint-v1';

export class CustodyError extends Error { constructor(message) { super(message); this.name = 'CustodyError'; } }

/** 시드 파일의 이름은 계정 파일에서 정한다 — 한 폴더의 여러 서비스(new_rp.sh)가 시드를 나눠 쓰지 않게. */
export function custodySeedFileOf(accountsFile) {
  const dir = path.dirname(accountsFile), base = path.basename(accountsFile);
  const m = /^(.*?)_?accounts\.json$/.exec(base);
  return path.join(dir, m ? `${m[1] ? `${m[1]}_` : ''}custody_seed.json` : `${base.replace(/\.json$/, '')}_custody_seed.json`);
}
/** SHA-256 앞 16바이트를 31비트 넷으로 — 강화 경로 네 단(124비트). 계정이 겹치지 않고, 한 계정의 키가 새도 다른 계정으로 번지지 않는다. */
function pathOf(domain, id) {
  const h = createHash('sha256').update(domain + id).digest();
  return `m/${[0, 4, 8, 12].map((o) => `${h.readUInt32BE(o) >>> 1}'`).join('/')}`;
}
function readSeed(file) {
  let st;
  try { st = fs.statSync(file); } catch { throw new CustodyError('보관 계정 시드 파일을 읽지 못했다'); }
  if (!st.isFile()) throw new CustodyError('보관 계정 시드 파일이 일반 파일이 아니다');
  if (process.platform !== 'win32' && (st.mode & 0o077)) throw new CustodyError('보관 계정 시드 파일의 권한이 0600 보다 넓다 — 권한을 확인할 것');
  let seed = null;
  try { const j = JSON.parse(fs.readFileSync(file, 'utf8')); if (j?.version === 1 && typeof j.seed === 'string' && /^[0-9a-f]{64}$/.test(j.seed)) seed = j.seed; } catch { seed = null; }
  if (!seed) throw new CustodyError('보관 계정 시드 파일의 모양이 틀리다 — 지우지 말고 확인할 것');
  return Buffer.from(seed, 'hex');
}
/** 이미 있는 파일은 덮지 않는다(wx). 다 쓰고 fsync 한 뒤에 연다 — 쓰다 만 파일로 기동하지 않게. */
function createSeed(file) {
  const seed = randomBytes(32).toString('hex');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let fd;
  try { fd = fs.openSync(file, 'wx', 0o600); } catch { throw new CustodyError('보관 계정 시드 파일을 만들지 못했다'); }
  try { fs.writeFileSync(fd, JSON.stringify({ version: 1, seed }) + '\n'); fs.fsyncSync(fd); }
  catch { fs.closeSync(fd); fd = undefined; try { fs.unlinkSync(file); } catch { /* 이미 없다 */ } throw new CustodyError('보관 계정 시드 파일을 쓰지 못했다'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
/**
 * 시드를 연다. expect(계정 파일에 적어 둔 지문)가 있으면 시드가 있어야 하고 지문이 같아야 한다 — 시드를 잃었을 때 조용히 새로 만들면 이전 주소의 돈을 잃는다.
 * expect 가 없으면(처음) 시드가 없을 때만 만든다.
 */
export function openCustody({ file, expect = null }) {
  if (!fs.existsSync(file)) {
    if (expect) throw new CustodyError('계정 파일에는 보관 계정의 지문이 있는데 시드 파일이 없다 — 시드를 되찾거나 두 파일을 함께 옮길 것');
    createSeed(file);
  }
  const root = HDNodeWallet.fromSeed(readSeed(file));
  const fingerprint = root.derivePath(pathOf('', FINGERPRINT_DOMAIN)).address;
  if (expect && expect !== fingerprint) throw new CustodyError('시드가 계정 파일의 지문과 다르다 — 다른 서비스의 시드이거나 새로 만든 시드다. 두 파일을 함께 옮길 것');
  const nodeOf = (id) => { if (typeof id !== 'string' || !id) throw new CustodyError('계정 id 가 없다'); return root.derivePath(pathOf(DOMAIN, id)); };
  return {
    fingerprint,
    addressOf: (id) => nodeOf(id).address,
    /** 보내기용 서명자 — 보낼 때마다 유도하고 어디에도 두지 않는다. */
    signerOf: (id, provider) => nodeOf(id).connect(provider),
  };
}
