/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package chain

// RegistryABI is the ABI of contracts/contracts/AttestationRegistry.sol.
//
// In a fuller build this file would be produced by `abigen` from the compiled
// artifact and would contain typed Go bindings. For the MVP we keep a single
// hand-maintained ABI constant and a thin typed wrapper in client.go; this
// avoids committing a large generated file while keeping the Go ⇄ Solidity
// contract explicit and reviewable. The ABI here MUST stay in sync with the
// Solidity source — the Hardhat tests are the authority on the contract shape.
const RegistryABI = `[
  {
    "type": "function",
    "name": "publish",
    "stateMutability": "nonpayable",
    "inputs": [
      { "name": "deploymentId", "type": "bytes32" },
      { "name": "configHash", "type": "bytes32" },
      { "name": "signature", "type": "bytes" },
      { "name": "signerFingerprint", "type": "bytes32" }
    ],
    "outputs": []
  },
  {
    "type": "function",
    "name": "getLatest",
    "stateMutability": "view",
    "inputs": [ { "name": "deploymentId", "type": "bytes32" } ],
    "outputs": [
      { "name": "configHash", "type": "bytes32" },
      { "name": "signature", "type": "bytes" },
      { "name": "signerFingerprint", "type": "bytes32" },
      { "name": "blockTimestamp", "type": "uint64" },
      { "name": "exists", "type": "bool" }
    ]
  },
  {
    "type": "event",
    "name": "AttestationPublished",
    "anonymous": false,
    "inputs": [
      { "name": "deploymentId", "type": "bytes32", "indexed": true },
      { "name": "configHash", "type": "bytes32", "indexed": false },
      { "name": "signerFingerprint", "type": "bytes32", "indexed": false },
      { "name": "blockTimestamp", "type": "uint64", "indexed": false }
    ]
  }
]`
