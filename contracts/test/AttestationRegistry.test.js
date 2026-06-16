const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AttestationRegistry", function () {
  async function deploy() {
    const [publisher, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AttestationRegistry");
    const reg = await Factory.deploy(publisher.address);
    await reg.waitForDeployment();
    return { reg, publisher, other };
  }

  const depId = ethers.keccak256(ethers.toUtf8Bytes("payments/api"));
  const cfg = ethers.keccak256(ethers.toUtf8Bytes("config-v1"));
  const fp = ethers.keccak256(ethers.toUtf8Bytes("kms-fingerprint"));
  // A representative ASN.1 DER ECDSA signature length (~70 bytes).
  const sig = "0x" + "ab".repeat(70);

  it("stores and returns the latest attestation", async function () {
    const { reg } = await deploy();

    await expect(reg.publish(depId, cfg, sig, fp))
      .to.emit(reg, "AttestationPublished")
      .withArgs(depId, cfg, fp, anyUint());

    const res = await reg.getLatest(depId);
    expect(res[0]).to.equal(cfg); // configHash
    expect(res[1]).to.equal(sig); // signature
    expect(res[2]).to.equal(fp); // signerFingerprint
    expect(res[3]).to.be.greaterThan(0n); // blockTimestamp
    expect(res[4]).to.equal(true); // exists
  });

  it("reports exists=false for an unknown deployment", async function () {
    const { reg } = await deploy();
    const res = await reg.getLatest(ethers.ZeroHash);
    expect(res[4]).to.equal(false);
  });

  it("overwrites the latest attestation on republish", async function () {
    const { reg } = await deploy();
    await reg.publish(depId, cfg, sig, fp);

    const cfg2 = ethers.keccak256(ethers.toUtf8Bytes("config-v2"));
    await reg.publish(depId, cfg2, sig, fp);

    const res = await reg.getLatest(depId);
    expect(res[0]).to.equal(cfg2);
  });

  it("rejects publish from a non-publisher", async function () {
    const { reg, other } = await deploy();
    await expect(
      reg.connect(other).publish(depId, cfg, sig, fp)
    ).to.be.revertedWithCustomError(reg, "NotPublisher");
  });

  it("rejects deployment with a zero publisher address", async function () {
    const Factory = await ethers.getContractFactory("AttestationRegistry");
    await expect(Factory.deploy(ethers.ZeroAddress)).to.be.revertedWith(
      "publisher is zero address"
    );
  });
});

// Helper: match any uint timestamp in withArgs.
function anyUint() {
  const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
  return anyValue;
}
