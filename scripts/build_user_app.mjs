// scripts/build_user_app.mjs — 브라우저 사용자 앱 번들(설계 2026-10-15 D5, 계획 R9). `npm run user:build`.
//   엔트리 두 개(페이지·증명 워커)를 ESM 으로 mode3/user/dist/ 에 낸다. Node 전용 모듈은 lib/browser/ shim 으로 바꿔 끼운다 —
//   공유 lib 는 고치지 않는다. snarkjs·ffjavascript 는 package.json 의 exports.browser(브라우저 빌드)로 자동 해석된다.
import * as esbuild from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SHIMS = { crypto: 'lib/browser/node_crypto.js', fs: 'lib/browser/node_fs.js', path: 'lib/browser/node_path.js', url: 'lib/browser/node_url.js' };
const nodeShims = {
  name: 'node-shims',
  setup(build) {
    build.onResolve({ filter: /^(node:)?(crypto|fs|path|url)$/ }, (args) => ({ path: path.join(ROOT, SHIMS[args.path.replace(/^node:/, '')]) }));
    // 그 밖의 node: 모듈이 끼어들면 조용히 빈 모듈이 되지 않고 빌드가 실패해야 한다 — esbuild 기본(platform:browser)이 그렇게 한다.
  },
};
const outdir = path.join(ROOT, 'mode3', 'user', 'dist');
const result = await esbuild.build({
  entryPoints: { user: path.join(ROOT, 'mode3/user/user.js'), prover_worker: path.join(ROOT, 'mode3/user/prover_worker.js') },
  bundle: true, format: 'esm', platform: 'browser', target: ['es2022'], outdir, sourcemap: true, logLevel: 'warning', metafile: true,
  plugins: [nodeShims],
  inject: [path.join(ROOT, 'lib/browser/globals_shim.js')],
  define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' },
});
const kb = (f) => Math.round(fs.statSync(path.join(outdir, f)).size / 1024);
console.log(`built mode3/user/dist/user.js (${kb('user.js')} KB), prover_worker.js (${kb('prover_worker.js')} KB)`);
// 남아 있는 node: 참조는 번들이 브라우저에서 import 실패로 죽는다는 뜻이다 — 여기서 잡는다.
for (const f of ['user.js', 'prover_worker.js']) {
  const src = fs.readFileSync(path.join(outdir, f), 'utf8');
  if (/from\s*["']node:/.test(src) || /require\(["']node:/.test(src)) { console.error(`${f}: node: 모듈 참조가 남아 있다`); process.exit(1); }
}
