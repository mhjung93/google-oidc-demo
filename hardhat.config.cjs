require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-ethernal");

// PPIDWallet.execute() exceeds the legacy codegen stack limit, so it needs the
// IR pipeline. PPIDWalletFactory imports PPIDWallet, and Hardhat compiles a
// dependency closure under one settings block, so the factory needs the very
// same settings — otherwise PPIDWallet would produce different bytecode
// depending on which compilation job built it, silently changing the CREATE2
// address the factory predicts. Both override keys must reference this one
// object so they cannot drift apart.
const WALLET_IR_SETTINGS = {
  viaIR: true,
  optimizer: { enabled: true, runs: 200 },
};

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
        settings: WALLET_IR_SETTINGS,
      },
      "contracts/PPIDWalletFactory.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
      },
      // v3 판도 같은 이유로 IR이 필요하고, 팩토리는 지갑을 import하므로 같은 설정을
      // 공유해야 CREATE2 주소가 컴파일 job에 따라 달라지지 않는다.
      "contracts/PPIDWalletV3.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
      },
      "contracts/PPIDWalletFactoryV3.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
      },
      // Mode3Wallet 도 같은 이유로 IR이 필요하고(execute 가 스택 한도를 넘는다), 팩토리가
      // 지갑을 import 하므로 같은 설정을 공유해야 CREATE2 주소가 컴파일 job 에 따라 달라지지 않는다.
      "contracts/Mode3Wallet.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
      },
      "contracts/Mode3WalletFactory.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
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
