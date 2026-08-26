// RevocationRegistry의 onlyIdP 주소와 IdP root 조회를 redeploy_ppid_factory.cjs와
// push_revocation_root.cjs가 공유한다. 두 스크립트가 서로 다른 주소를 쓰면
// pushRoot가 NotIdP로 revert하므로 한 곳에서만 결정한다.
//
// 이 주소는 보안 경계다: 이 키를 가진 사람은 임의의 bytes32를 root로 게시할 수 있고,
// 폐기 이전 시점의 옛 root를 다시 올려 전원의 폐기를 되돌릴 수 있다. 그래서 미설정 시
// 배포자 주소로 조용히 대체하지 않고 명확한 에러로 중단한다 — 운영자가 이 주소를
// 의식적으로 고르게 하기 위함이다.
const IDP_ADDRESS_ENV = "REVOCATION_IDP_ADDRESS";

function requireIdPAddress(hre) {
  const raw = process.env[IDP_ADDRESS_ENV];
  if (!raw) {
    throw new Error(
      `${IDP_ADDRESS_ENV}가 설정되지 않았습니다. RevocationRegistry의 onlyIdP 주소는 ` +
      `보안 경계이므로 배포자 주소로 대체하지 않습니다. 폐기 root를 게시할 운영자 계정 주소를 ` +
      `명시적으로 지정하세요:\n  ${IDP_ADDRESS_ENV}=0x... npx hardhat run <script> --network localhost`
    );
  }
  try {
    return hre.ethers.getAddress(raw.trim());
  } catch {
    throw new Error(`${IDP_ADDRESS_ENV}가 올바른 이더리움 주소가 아닙니다: ${raw}`);
  }
}

// pushRoot는 onlyIdP다. 로컬 데모 체인에서는 노드가 계정을 unlock해 주므로
// 그 주소에 해당하는 signer를 찾아 쓴다. 없으면 조용히 기본 signer로 떨어지지 않고
// 중단한다(그랬다간 NotIdP revert가 나거나, 더 나쁘게는 잘못된 주소로 배포된다).
async function getIdPSigner(hre) {
  const address = requireIdPAddress(hre);
  const signers = await hre.ethers.getSigners();
  const signer = signers.find((s) => hre.ethers.getAddress(s.address) === address);
  if (!signer) {
    throw new Error(
      `${IDP_ADDRESS_ENV}=${address}에 해당하는 signer가 네트워크 "${hre.network.name}"에 없습니다. ` +
      `이 주소로는 pushRoot를 보낼 수 없습니다(onlyIdP). 노드가 해당 계정을 제공하는지 확인하세요.`
    );
  }
  return signer;
}

async function fetchIdPRoot(idpBaseUrl) {
  let res;
  try {
    res = await fetch(`${idpBaseUrl}/idp/revocation_state`);
  } catch (err) {
    throw new Error(`IdP(${idpBaseUrl})에 연결할 수 없어 폐기 root를 가져오지 못했습니다: ${err.message}`);
  }
  if (!res.ok) throw new Error(`revocation_state failed (${idpBaseUrl}): ${res.status}`);
  const { root } = await res.json();
  if (root === undefined || root === null) {
    throw new Error(`revocation_state 응답에 root가 없습니다 (${idpBaseUrl})`);
  }
  return String(root);
}

// 회로의 root는 필드 요소(10진 문자열)이고 컨트랙트는 bytes32를 받는다.
function rootToBytes32(hre, root) {
  return hre.ethers.zeroPadValue(hre.ethers.toBeHex(BigInt(root)), 32);
}

module.exports = { IDP_ADDRESS_ENV, requireIdPAddress, getIdPSigner, fetchIdPRoot, rootToBytes32 };
