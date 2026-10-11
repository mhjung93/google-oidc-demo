// SVG → PNG (크롬 헤드리스, Playwright channel chrome). 사용: node docs/paper/zkd/render_svg.mjs <src.svg> <dst.png> [scale=2]
// SVG 의 width/height 를 viewport 로 쓰고 scale 배로 찍는다. fig1_overview_v6.svg·fig1_boxes_v6.svg 의 PNG 는 이것으로 만든다.
import { chromium } from 'playwright';
import path from 'node:path';
import fs from 'node:fs';
const [,, src, dst, scale] = process.argv;
const svg = fs.readFileSync(src, 'utf8');
const w = Number(/width="(\d+)"/.exec(svg)[1]), h = Number(/height="(\d+)"/.exec(svg)[1]);
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: Number(scale || 2) });
await page.goto('file://' + path.resolve(src));
await page.waitForTimeout(300);
await page.screenshot({ path: dst, fullPage: false });
await browser.close();
console.log('rendered', dst, `${w}x${h} @${scale || 2}x`);
