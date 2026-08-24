require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-ethernal");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    compilers: [{ version: "0.8.24" }],
    // PPIDWallet.execute()가 revocationRoot 파라미터 추가로 EVM 스택 한도(16
    // slot)를 넘어 "stack too deep"이 나서, 이 파일만 viaIR로 컴파일한다.
    // PPIDWalletFactory.sol도 PPIDWallet.sol을 import하므로, 그쪽 진입점으로
    // 만들어지는 컴파일 job에서도 PPIDWallet.sol이 기본 설정(비-viaIR)으로
    // 다시 컴파일되지 않도록 같은 override를 걸어준다.
    overrides: {
      "contracts/PPIDWallet.sol": {
        version: "0.8.24",
        settings: {
          viaIR: true,
          optimizer: { enabled: true, runs: 200 },
        },
      },
      "contracts/PPIDWalletFactory.sol": {
        version: "0.8.24",
        settings: {
          viaIR: true,
          optimizer: { enabled: true, runs: 200 },
        },
      },
    },
  },
  ethernal: {
    apiToken: process.env.ETHERNAL_API_TOKEN,
    workspace: process.env.ETHERNAL_WORKSPACE, // 선택
    resetOnStart: process.env.ETHERNAL_WORKSPACE, // 선택(노드 재시작 시 workspace 초기화)
    verbose: true, // 선택(문제 생기면 로그)
  },
};
