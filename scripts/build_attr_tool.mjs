// scripts/build_attr_tool.mjs — 속성 커밋먼트 도구 번들(2026-11-09 Phase 1). `npm run attr:build` → mode3/attr/dist/attr.js.
//   build_user_app.mjs 와 같은 shim(lib/browser/)으로 node: 모듈을 바꿔 끼운다. 출력은 IIFE 하나(window.Mode3Attr) — attr.html 이
//   <script> 로 읽는다. 지갑 에이전트가 /attr/dist/attr.js 로 서빙한다(mode3_wallet_agent.js).
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
  },
};
const outdir = path.join(ROOT, 'mode3', 'attr', 'dist');
await esbuild.build({
  entryPoints: { attr: path.join(ROOT, 'mode3/attr/attr_core.js') },
  bundle: true, format: 'iife', globalName: 'Mode3Attr', platform: 'browser', target: ['es2022'], outdir, sourcemap: true, logLevel: 'warning',
  plugins: [nodeShims],
  inject: [path.join(ROOT, 'lib/browser/globals_shim.js')],
  define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' },
});
const out = path.join(outdir, 'attr.js');
console.log(`built mode3/attr/dist/attr.js (${Math.round(fs.statSync(out).size / 1024)} KB)`);
const src = fs.readFileSync(out, 'utf8');
if (/from\s*["']node:/.test(src) || /require\(["']node:/.test(src)) { console.error('attr.js: node: 모듈 참조가 남아 있다'); process.exit(1); }
