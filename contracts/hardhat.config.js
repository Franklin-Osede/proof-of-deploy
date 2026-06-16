require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const RPC_URL = process.env.RPC_URL || "";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "";

// Only attach an account if a key is present, so `npx hardhat test` works
// against the in-process network without any configuration.
const accounts = PRIVATE_KEY ? [PRIVATE_KEY] : [];

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    // Base Sepolia testnet — chainId 84532. NO real funds.
    baseSepolia: {
      url: RPC_URL || "https://sepolia.base.org",
      chainId: 84532,
      accounts,
    },
    // Polygon Amoy testnet — chainId 80002. NO real funds.
    polygonAmoy: {
      url: RPC_URL || "https://rpc-amoy.polygon.technology",
      chainId: 80002,
      accounts,
    },
  },
};
