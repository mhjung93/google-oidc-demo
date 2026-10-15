// mode3/user/user.js — 사용자 페이지 엔트리(Task 9 가 실제 내용으로 바꾼다). 지금은 공유 lib 가 브라우저 번들에 들어가는지만 증명한다.
import { ethers } from 'ethers';
import { createRegistration, normalizeDisclosure } from '../../lib/mode3_wallet.js';
import { payloadDigest, PUB_INDEX } from '../../lib/mode3_onchain.js';
import { loadSchema, DEFAULT_ATTR_SCHEMA } from '../../lib/mode3_attr_schema.js';
import { originToField } from '../../lib/mode3_rp_cert.js';
console.log('mode3 user bundle ok', ethers.version, PUB_INDEX.COUNT, loadSchema(DEFAULT_ATTR_SCHEMA).hash.slice(0, 8), originToField('http://127.0.0.1:3100').toString().slice(0, 6));
window.__mode3UserSmoke = async () => { const r = await createRegistration(12345n); return { auid: r.auid.toString(), mask: normalizeDisclosure(null, []).mask.toString(), digest: payloadDigest({ chainId: 31337n, wallet: ethers.ZeroAddress, to: ethers.ZeroAddress, value: 0n, data: '0x', nonce: 0n, maxHeight: 1n, allowAgent: 0n, tagC1X: 0n, tagC1Y: 0n, tagC2: 0n }) }; };
