// 서비스 챌린지 수명과 승인 창 대기 시간의 정적 검사(2026-11-18 전체 리뷰 1).
// 챌린지(r_s)는 승인 창을 열기 전에 발급되고 창이 끝난 뒤 /api/mode3/login 에서 소비된다 — 수명이 창 대기 시간보다 짧으면
// 창은 "로그인 성공" 으로 닫히는데 서비스가 bad_challenge 로 거절한다(첫 로그인은 등록·발급·게시 대기·증명이 한 창에서 돈다).
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = (rel) => fs.readFileSync(new URL(rel, import.meta.url), 'utf8');
const num = (s) => Number(s.replaceAll('_', ''));

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

t('챌린지 수명 기본값은 승인 창 대기 시간보다 길다', () => {
  const ttl = read('../mode3_rp.js').match(/const CHALLENGE_TTL_MS = Number\(process\.env\.MODE3_CHALLENGE_TTL_MS\) \|\| ([\d_]+);/);
  const popup = read('../mode3/rp.html').match(/const POPUP_TIMEOUT_MS = ([\d_]+);/);
  assert.ok(ttl, 'mode3_rp.js 에서 CHALLENGE_TTL_MS 기본값을 찾지 못했다');
  assert.ok(popup, 'mode3/rp.html 에서 POPUP_TIMEOUT_MS 를 찾지 못했다');
  assert.ok(num(ttl[1]) > num(popup[1]), `챌린지 수명 ${num(ttl[1])}ms ≤ 승인 창 대기 ${num(popup[1])}ms`);
});

console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
