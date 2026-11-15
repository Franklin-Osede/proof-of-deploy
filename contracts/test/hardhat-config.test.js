const { expect } = require("chai");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

// With RPC_URL unset, the testnet networks must not exist at all: no public
// default endpoint may be filled in. This loads the real hardhat.config.js in a
// child Hardhat process and never contacts any network:
//   - RPC_URL, PRIVATE_KEY and DEMO_RPC_URL are removed from the child env;
//   - the config is copied into a fresh temp project (node_modules symlinked),
//     so dotenv finds no contracts/.env that could reintroduce RPC_URL;
//   - Hardhat throws HH100 while building the runtime environment, before any
//     task, provider, analytics or version check runs. CI=true and a piped
//     (non-TTY) stdout keep Hardhat's optional outbound paths disabled anyway.
describe("hardhat.config.js with RPC_URL unset", function () {
  this.timeout(60_000);

  const contractsDir = path.join(__dirname, "..");
  const configFile = path.join(contractsDir, "hardhat.config.js");
  let tmp;

  before(function () {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hh-config-"));
    fs.copyFileSync(configFile, path.join(tmp, "hardhat.config.js"));
    fs.symlinkSync(path.join(contractsDir, "node_modules"), path.join(tmp, "node_modules"), "dir");
  });

  after(function () {
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  });

  function runHardhat(args) {
    const env = { ...process.env, CI: "true", HARDHAT_DISABLE_TELEMETRY_PROMPT: "true" };
    for (const k of ["RPC_URL", "PRIVATE_KEY", "DEMO_RPC_URL", "HARDHAT_NETWORK"]) delete env[k];
    const cli = path.join(tmp, "node_modules", "hardhat", "internal", "cli", "cli.js");
    return spawnSync(process.execPath, [cli, ...args], { cwd: tmp, env, encoding: "utf8" });
  }

  for (const network of ["baseSepolia", "polygonAmoy"]) {
    it(`leaves ${network} undefined instead of using a public default`, function () {
      const res = runHardhat(["--network", network, "check"]);
      const out = res.stdout + res.stderr;
      // Reaching HH100 also proves the config loaded without throwing.
      expect(res.status, out).to.equal(1);
      expect(out).to.include(`HH100: Network ${network} doesn't exist`);
    });
  }

  it("contains no hard-coded http(s) RPC URL", function () {
    const src = fs.readFileSync(configFile, "utf8");
    expect(src).to.not.match(/https?:\/\//);
  });
});
