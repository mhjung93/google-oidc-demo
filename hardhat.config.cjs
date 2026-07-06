require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-ethernal");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.24",
  ethernal: {
    apiToken: process.env.ETHERNAL_API_TOKEN,
    workspace: process.env.ETHERNAL_WORKSPACE, // 선택
    resetOnStart: process.env.ETHERNAL_WORKSPACE, // 선택(노드 재시작 시 workspace 초기화)
    verbose: true, // 선택(문제 생기면 로그)
  },
};
