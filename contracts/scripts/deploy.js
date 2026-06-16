// Deploys AttestationRegistry to the configured network.
//
// The deployer account (PRIVATE_KEY) becomes the immutable `publisher`. This is
// the SAME testnet wallet the operator uses as ETH_PRIVATE_KEY to publish
// attestations. NEVER use a mainnet key or a key with real funds.
//
// Usage:
//   npx hardhat run scripts/deploy.js --network baseSepolia
const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error("No signer available. Set PRIVATE_KEY in contracts/.env");
  }

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Network:   ${network.name}`);
  console.log(`Deployer:  ${deployer.address}`);
  console.log(`Balance:   ${ethers.formatEther(balance)} (testnet)`);

  const Factory = await ethers.getContractFactory("AttestationRegistry");
  const reg = await Factory.deploy(deployer.address);
  await reg.waitForDeployment();

  const addr = await reg.getAddress();
  console.log("");
  console.log("AttestationRegistry deployed.");
  console.log(`  address:   ${addr}`);
  console.log(`  publisher: ${deployer.address}`);
  console.log("");
  console.log("Set this in the operator and CLI environment:");
  console.log(`  CONTRACT_ADDRESS=${addr}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
