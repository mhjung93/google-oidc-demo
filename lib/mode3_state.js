// JSON 상태 파일 원자적 읽기/쓰기. custom_idp.js 의 writeSecretFile 과 같은 방식이다 —
// 임시 파일에 쓰고 fsync 한 뒤 rename 으로 교체해 부분 상태가 관측되지 않게 한다.
// Mode 2 파일을 import 하지 않는 이유는 그쪽이 import 만으로 서버를 띄우기 때문이다.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

export function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function writeJsonAtomic(file, obj, mode = 0o600) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, JSON.stringify(obj, null, 2));
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch { /* best-effort */ }
    throw err;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* best-effort */ }
    throw err;
  }
}
