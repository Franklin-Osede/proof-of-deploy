const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("AttestationRegistry", function () {
  async function deploy() {
    const [publisher, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AttestationRegistry");
    const reg = await Factory.deploy(publisher.address);
    await reg.waitForDeployment();
    return { reg, publisher, other };
  }

  // Opaque bytes32 values. The contract never interprets them, so keccak is a
  // fine source of test data even though the protocol itself uses SHA-256.
  const depId = ethers.keccak256(ethers.toUtf8Bytes("payments/api"));
  const cfg = ethers.keccak256(ethers.toUtf8Bytes("config-v1"));
  const fp = ethers.keccak256(ethers.toUtf8Bytes("kms-fingerprint"));
  // A representative ASN.1 DER ECDSA signature length (~70 bytes).
  const sig = "0x" + "ab".repeat(70);
  const V1 = 1;

  it("stores and returns the latest attestation", async function () {
    const { reg } = await deploy();

    await expect(reg.publish(depId, V1, cfg, sig, fp))
      .to.emit(reg, "AttestationPublished")
      .withArgs(depId, V1, cfg, fp, anyValue);

    const res = await reg.getLatest(depId);
    expect(res[0]).to.equal(cfg); // configHash
    expect(res[1]).to.equal(sig); // signature
    expect(res[2]).to.equal(fp); // signerFingerprint
    expect(res[3]).to.be.greaterThan(0n); // blockTimestamp
    expect(res[4]).to.equal(BigInt(V1)); // hashVersion
    expect(res[5]).to.equal(true); // exists
  });

  it("reports exists=false and hashVersion=0 for an unknown deployment", async function () {
    const { reg } = await deploy();
    const res = await reg.getLatest(ethers.ZeroHash);
    expect(res[4]).to.equal(0n); // hashVersion
    expect(res[5]).to.equal(false); // exists
  });

  it("overwrites the latest attestation on republish", async function () {
    const { reg } = await deploy();
    await reg.publish(depId, V1, cfg, sig, fp);

    const cfg2 = ethers.keccak256(ethers.toUtf8Bytes("config-v2"));
    await reg.publish(depId, V1, cfg2, sig, fp);

    const res = await reg.getLatest(depId);
    expect(res[0]).to.equal(cfg2);
  });

  it("carries a new hash version through an overwrite", async function () {
    // A protocol upgrade republishes the same Deployment under a new version.
    // The record must report the version that produced the stored hash, or a
    // verifier would recompute with the wrong normalizer.
    const { reg } = await deploy();
    await reg.publish(depId, V1, cfg, sig, fp);

    const cfgV2 = ethers.keccak256(ethers.toUtf8Bytes("config-under-v2"));
    await reg.publish(depId, 2, cfgV2, sig, fp);

    const res = await reg.getLatest(depId);
    expect(res[0]).to.equal(cfgV2);
    expect(res[4]).to.equal(2n);
  });

  it("rejects hash version zero", async function () {
    // Zero is what an unset struct reads back as, so accepting it would make
    // "never published" indistinguishable from "published under version 0".
    const { reg } = await deploy();
    await expect(
      reg.publish(depId, 0, cfg, sig, fp)
    ).to.be.revertedWithCustomError(reg, "InvalidHashVersion");
  });

  it("accepts an unknown-but-nonzero version without interpreting it", async function () {
    // The contract is not the arbiter of which versions exist; rejecting
    // unknown versions is the verifier's job. Storing one must not revert, or
    // a protocol upgrade would require a contract upgrade.
    const { reg } = await deploy();
    await reg.publish(depId, 65535, cfg, sig, fp);
    expect((await reg.getLatest(depId))[4]).to.equal(65535n);
  });

  it("indexes hashVersion so consumers can filter by protocol", async function () {
    const { reg } = await deploy();
    await reg.publish(depId, V1, cfg, sig, fp);
    await reg.publish(depId, 2, cfg, sig, fp);

    const v2Only = await reg.queryFilter(reg.filters.AttestationPublished(null, 2));
    expect(v2Only.length).to.equal(1);
    expect(v2Only[0].args.hashVersion).to.equal(2n);
  });

  it("rejects publish from a non-publisher", async function () {
    const { reg, other } = await deploy();
    await expect(
      reg.connect(other).publish(depId, V1, cfg, sig, fp)
    ).to.be.revertedWithCustomError(reg, "NotPublisher");
  });

  it("rejects deployment with a zero publisher address", async function () {
    const Factory = await ethers.getContractFactory("AttestationRegistry");
    await expect(Factory.deploy(ethers.ZeroAddress)).to.be.revertedWith(
      "publisher is zero address"
    );
  });
});
