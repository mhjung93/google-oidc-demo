// lib/browser/globals_shim.js — esbuild `inject` 로 모든 엔트리 맨 앞에 들어간다. circomlibjs(eddsa·blake-hash)와 우리 lib 가 전역 Buffer 를 쓰고,
// 일부 라이브러리가 typeof 검사 없이 process.env 를 읽는다.
// 'buffer' 는 node_modules 에 전이 의존성(6.0.3)으로 있다 — devDependencies 명시는 사용자 승인 대기(계획 Task 4 Ruling).
import { Buffer } from 'buffer';
if (!globalThis.Buffer) globalThis.Buffer = Buffer;
if (!globalThis.process) globalThis.process = { env: {}, browser: true };
