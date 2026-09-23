// publishRoot 가스 실측 — 로컬 hardhat 에 새 RevocationLog 를 배포하고 리프 1·10·100개 게시.
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from '/home/node1phi/Desktop/google-oidc-demo/tests/helpers/mode3_chain.mjs';
import { createRevocationTree, userLeaf } from '/home/node1phi/Desktop/google-oidc-demo/lib/mode3_revocation.js';
const provider = getProvider();
const cia = ethers.Wallet.createRandom().connect(provider);
await fundAddress(cia.address, '1', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(cia.address, provider);
const tree = await createRevocationTree();
let epoch = 0n, next = 1n;
const out = [];
for (const n of [1, 10, 100]) {
  const leaves = [];
  for (let i = 0; i < n; i++) { const l = await userLeaf(next++); await tree.insert(l); leaves.push(rootToBytes32(l)); }
  epoch += 1n;
  const root = rootToBytes32(tree.getRoot());
  const sig = await signRootPublication(cia, { logAddress, root, epoch, leaves });
  const rc = await (await log.connect(cia).publishRoot(root, epoch, leaves, sig)).wait();
  out.push({ leaves: n, gasUsed: Number(rc.gasUsed) });
}
console.log(JSON.stringify(out));
provider.destroy(); process.exit(0);
