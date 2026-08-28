const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const fs = require("fs");
const path = require("path");

// The fixture values come from the Go golden vectors rather than being invented
// here. If the two sides ever disagree about widths or encoding, that is exactly
// the failure this coupling is meant to surface -- the contract stores what the
// protocol produces, not something that merely looks similar.
function goldenVectors() {
  const file = path.join(
    __dirname, "..", "..", "internal", "attest", "testdata", "_envelope_v2", "reference.txt"
  );
  const out = {};
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const m = line.match(/^(\S+)\s+([0-9a-f]+)$/);
    if (m) out[m[1]] = "0x" + m[2];
  }
  for (const k of ["workloadID", "incarnation", "signingDigest"]) {
    if (!out[k]) throw new Error(`golden vector ${k} missing from reference.txt`);
  }
  return out;
}

describe("AttestationRegistryV2", function () {
  const G = goldenVectors();
  const workloadId = G.workloadID;
  const incarnation = G.incarnation;
  // The config hash of the demo workload, which the Go fixtures also use.
  const cfg = "0x89ab57526b689c52761431af4bc5451933c1947b74e0db262438ad1881c17a77";
  const fp = ethers.keccak256(ethers.toUtf8Bytes("kms-fingerprint"));
  const sig = "0x" + "ab".repeat(70); // representative ASN.1 DER ECDSA length
  const V1 = 1;

  async function deploy() {
    const [publisher, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AttestationRegistryV2");
    const reg = await Factory.deploy(publisher.address);
    await reg.waitForDeployment();
    return { reg, publisher, other };
  }

  it("uses fixed-width fields matching the Go golden vectors", function () {
    // 32 bytes each: a mismatch here means the Go and Solidity sides disagree
    // about what an identity or an incarnation is.
    expect(ethers.dataLength(workloadId)).to.equal(32);
    expect(ethers.dataLength(incarnation)).to.equal(32);
    expect(ethers.dataLength(cfg)).to.equal(32);
  });

  it("stores and returns every field", async function () {
    const { reg } = await deploy();
    await reg.publish(workloadId, V1, cfg, incarnation, sig, fp);

    const r = await reg.getLatest(workloadId);
    expect(r[0]).to.equal(cfg);
    expect(r[1]).to.equal(sig);
    expect(r[2]).to.equal(fp);
    expect(r[3]).to.equal(incarnation);
    expect(r[4]).to.be.greaterThan(0n); // blockTimestamp
    expect(r[5]).to.equal(BigInt(V1)); // hashVersion
    expect(r[6]).to.equal(true); // exists
  });

  it("emits an event carrying exactly what it stored", async function () {
    // Storage is latest-only, so the event is the only durable record of a
    // superseded attestation. If the two can drift, history becomes fiction.
    const { reg } = await deploy();
    const tx = await reg.publish(workloadId, V1, cfg, incarnation, sig, fp);
    const receipt = await tx.wait();

    const ev = receipt.logs
      .map((l) => reg.interface.parseLog(l))
      .find((l) => l && l.name === "AttestationPublished");
    expect(ev, "AttestationPublished not emitted").to.not.be.undefined;

    const r = await reg.getLatest(workloadId);
    expect(ev.args.workloadId).to.equal(workloadId);
    expect(ev.args.hashVersion).to.equal(r[5]);
    expect(ev.args.configHash).to.equal(r[0]);
    expect(ev.args.incarnation).to.equal(r[3]);
    expect(ev.args.signerFingerprint).to.equal(r[2]);
    expect(ev.args.signature).to.equal(r[1]);
    expect(ev.args.blockTimestamp).to.equal(r[4]);
  });

  it("keeps a superseded attestation verifiable through logs", async function () {
    // The v1 event omitted the signature, so once a record was overwritten the
    // previous attestation could never be checked again.
    const { reg } = await deploy();
    await reg.publish(workloadId, V1, cfg, incarnation, sig, fp);

    const cfg2 = ethers.keccak256(ethers.toUtf8Bytes("later-config"));
    const sig2 = "0x" + "cd".repeat(70);
    await reg.publish(workloadId, V1, cfg2, incarnation, sig2, fp);

    const events = await reg.queryFilter(reg.filters.AttestationPublished(workloadId));
    expect(events.length).to.equal(2);
    // The superseded record is fully recoverable, signature included.
    expect(events[0].args.configHash).to.equal(cfg);
    expect(events[0].args.signature).to.equal(sig);
    expect((await reg.getLatest(workloadId))[0]).to.equal(cfg2);
  });

  it("separates the same namespace/name in different clusters", async function () {
    // The defect v2 exists to fix. These ids differ only because the cluster
    // differs; under v1 both would be SHA-256("payments/api") and collide.
    const { reg } = await deploy();
    const clusterA = ethers.sha256(ethers.toUtf8Bytes("cluster-a|apps/v1|Deployment|payments|api"));
    const clusterB = ethers.sha256(ethers.toUtf8Bytes("cluster-b|apps/v1|Deployment|payments|api"));
    expect(clusterA).to.not.equal(clusterB);

    const cfgB = ethers.keccak256(ethers.toUtf8Bytes("different-config"));
    await reg.publish(clusterA, V1, cfg, incarnation, sig, fp);
    await reg.publish(clusterB, V1, cfgB, incarnation, sig, fp);

    expect((await reg.getLatest(clusterA))[0]).to.equal(cfg);
    expect((await reg.getLatest(clusterB))[0]).to.equal(cfgB);
  });

  it("reports an unknown workload as absent with all fields zero", async function () {
    const { reg } = await deploy();
    const r = await reg.getLatest(ethers.ZeroHash);
    expect(r[6]).to.equal(false); // exists
    expect(r[5]).to.equal(0n); // hashVersion
    expect(r[3]).to.equal(ethers.ZeroHash); // incarnation
    expect(r[1]).to.equal("0x"); // signature
  });

  it("carries a new hash version through an overwrite", async function () {
    const { reg } = await deploy();
    await reg.publish(workloadId, V1, cfg, incarnation, sig, fp);
    const cfgV2 = ethers.keccak256(ethers.toUtf8Bytes("config-under-v2"));
    await reg.publish(workloadId, 2, cfgV2, incarnation, sig, fp);

    const r = await reg.getLatest(workloadId);
    expect(r[0]).to.equal(cfgV2);
    expect(r[5]).to.equal(2n);
  });

  it("rejects hash version zero", async function () {
    const { reg } = await deploy();
    await expect(
      reg.publish(workloadId, 0, cfg, incarnation, sig, fp)
    ).to.be.revertedWithCustomError(reg, "InvalidHashVersion");
  });

  it("rejects an empty signature", async function () {
    const { reg } = await deploy();
    await expect(
      reg.publish(workloadId, V1, cfg, incarnation, "0x", fp)
    ).to.be.revertedWithCustomError(reg, "EmptySignature");
  });

  it("accepts an unknown-but-nonzero version without interpreting it", async function () {
    // Deciding which versions exist is the verifier's job. If the contract
    // policed it, a protocol upgrade would require a contract upgrade.
    const { reg } = await deploy();
    await reg.publish(workloadId, 65535, cfg, incarnation, sig, fp);
    expect((await reg.getLatest(workloadId))[5]).to.equal(65535n);
  });

  it("accepts a zero incarnation without interpreting it", async function () {
    // Zero means "no incarnation bound". Treating that as weaker than a bound
    // one is a verifier decision, so the contract stores it rather than
    // rejecting it.
    const { reg } = await deploy();
    await reg.publish(workloadId, V1, cfg, ethers.ZeroHash, sig, fp);
    const r = await reg.getLatest(workloadId);
    expect(r[3]).to.equal(ethers.ZeroHash);
    expect(r[6]).to.equal(true);
  });

  it("indexes workloadId and hashVersion for filtering", async function () {
    const { reg } = await deploy();
    await reg.publish(workloadId, V1, cfg, incarnation, sig, fp);
    await reg.publish(workloadId, 2, cfg, incarnation, sig, fp);

    const v2Only = await reg.queryFilter(reg.filters.AttestationPublished(null, 2));
    expect(v2Only.length).to.equal(1);
    expect(v2Only[0].args.hashVersion).to.equal(2n);
  });

  it("rejects publish from a non-publisher", async function () {
    const { reg, other } = await deploy();
    await expect(
      reg.connect(other).publish(workloadId, V1, cfg, incarnation, sig, fp)
    ).to.be.revertedWithCustomError(reg, "NotPublisher");
  });

  it("rejects deployment with a zero publisher address", async function () {
    const Factory = await ethers.getContractFactory("AttestationRegistryV2");
    await expect(Factory.deploy(ethers.ZeroAddress)).to.be.revertedWith(
      "publisher is zero address"
    );
  });

  it("has no way to rotate the publisher", async function () {
    // Immutability is the design, not an omission. If this ever gains a
    // setter, the trust model changed and the ADR must change with it.
    const { reg } = await deploy();
    const names = reg.interface.fragments
      .filter((f) => f.type === "function")
      .map((f) => f.name);
    expect(names).to.have.members(["publisher", "publish", "getLatest"]);
  });
});
