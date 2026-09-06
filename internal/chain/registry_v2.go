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

// RegistryV2ABI is the ABI of contracts/contracts/AttestationRegistryV2.sol.
//
// Generated once from the compiled artifact rather than transcribed by hand,
// then guarded by TestABIMatchesCompiledArtifact, which compares every entry
// declared here against that artifact on every CI run. Editing this constant
// without a matching Solidity change fails the build.
//
// Only the entries the Go side actually uses are declared. publisher() is here
// because startup validation reads it: the address it returns is spliced into
// the runtime template to prove the deployed code really is this contract,
// compiled for this publisher.
const RegistryV2ABI = `[
  {
    "type": "event",
    "name": "AttestationPublished",
    "anonymous": false,
    "inputs": [
      {
        "name": "workloadId",
        "type": "bytes32",
        "indexed": true
      },
      {
        "name": "hashVersion",
        "type": "uint16",
        "indexed": true
      },
      {
        "name": "configHash",
        "type": "bytes32",
        "indexed": false
      },
      {
        "name": "incarnation",
        "type": "bytes32",
        "indexed": false
      },
      {
        "name": "signerFingerprint",
        "type": "bytes32",
        "indexed": false
      },
      {
        "name": "signature",
        "type": "bytes",
        "indexed": false
      },
      {
        "name": "blockTimestamp",
        "type": "uint64",
        "indexed": false
      }
    ]
  },
  {
    "type": "function",
    "name": "getLatest",
    "stateMutability": "view",
    "inputs": [
      {
        "name": "workloadId",
        "type": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "configHash",
        "type": "bytes32"
      },
      {
        "name": "signature",
        "type": "bytes"
      },
      {
        "name": "signerFingerprint",
        "type": "bytes32"
      },
      {
        "name": "incarnation",
        "type": "bytes32"
      },
      {
        "name": "blockTimestamp",
        "type": "uint64"
      },
      {
        "name": "hashVersion",
        "type": "uint16"
      },
      {
        "name": "exists",
        "type": "bool"
      }
    ]
  },
  {
    "type": "function",
    "name": "publish",
    "stateMutability": "nonpayable",
    "inputs": [
      {
        "name": "workloadId",
        "type": "bytes32"
      },
      {
        "name": "hashVersion",
        "type": "uint16"
      },
      {
        "name": "configHash",
        "type": "bytes32"
      },
      {
        "name": "incarnation",
        "type": "bytes32"
      },
      {
        "name": "signature",
        "type": "bytes"
      },
      {
        "name": "signerFingerprint",
        "type": "bytes32"
      }
    ],
    "outputs": []
  },
  {
    "type": "function",
    "name": "publisher",
    "stateMutability": "view",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address"
      }
    ]
  }
]`
