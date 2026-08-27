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

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// artifactPath is where Hardhat writes the compiled contract. It is gitignored,
// so this test skips when the contracts have not been built. CI compiles them
// first, which is what makes the check real rather than decorative.
const artifactPath = "../../contracts/artifacts/contracts/AttestationRegistry.sol/AttestationRegistry.json"

// abiEntry is the subset of an ABI item that determines call encoding. Anything
// outside it (ordering of unrelated entries, doc fields) is not part of the
// wire contract and is deliberately not compared.
type abiEntry struct {
	Type            string     `json:"type"`
	Name            string     `json:"name"`
	StateMutability string     `json:"stateMutability"`
	Inputs          []abiParam `json:"inputs"`
	Outputs         []abiParam `json:"outputs"`
}

type abiParam struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Indexed bool   `json:"indexed"`
}

func index(t *testing.T, raw []byte, what string) map[string]abiEntry {
	t.Helper()
	var entries []abiEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse %s ABI: %v", what, err)
	}
	out := make(map[string]abiEntry, len(entries))
	for _, e := range entries {
		if e.Type == "function" || e.Type == "event" {
			out[e.Type+" "+e.Name] = e
		}
	}
	return out
}

// TestABIMatchesCompiledArtifact closes the drift gap between the
// hand-maintained Go ABI and the Solidity source.
//
// Without it, a change to a function signature compiles and passes the Hardhat
// tests on the Solidity side while the operator keeps encoding calls the old
// way. The failure would surface only at runtime, against a real chain, as a
// reverted or silently misencoded transaction.
func TestABIMatchesCompiledArtifact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(artifactPath))
	if err != nil {
		t.Skipf("compiled artifact not found (run `make contracts-compile`): %v", err)
	}
	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}

	want := index(t, artifact.ABI, "compiled")
	got := index(t, []byte(RegistryABI), "Go")

	// Every entry the Go client declares must match Solidity exactly. The Go
	// side may legitimately omit entries it never calls, so the comparison is
	// one-directional -- but a mismatch on anything declared is a bug.
	for key, g := range got {
		w, ok := want[key]
		if !ok {
			t.Errorf("%s is declared in RegistryABI but does not exist in the contract", key)
			continue
		}
		if g.StateMutability != w.StateMutability {
			t.Errorf("%s: stateMutability is %q in Go, %q in Solidity", key, g.StateMutability, w.StateMutability)
		}
		compareParams(t, key+" inputs", g.Inputs, w.Inputs)
		compareParams(t, key+" outputs", g.Outputs, w.Outputs)
	}

	// publish and getLatest are what the operator and CLI actually depend on,
	// so their absence must fail rather than silently pass an empty loop.
	for _, required := range []string{"function publish", "function getLatest", "event AttestationPublished"} {
		if _, ok := got[required]; !ok {
			t.Errorf("RegistryABI no longer declares %s", required)
		}
	}
}

func compareParams(t *testing.T, what string, got, want []abiParam) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %d params in Go, %d in Solidity", what, len(got), len(want))
		return
	}
	for i := range got {
		if got[i].Type != want[i].Type {
			t.Errorf("%s[%d] (%s): type is %q in Go, %q in Solidity",
				what, i, want[i].Name, got[i].Type, want[i].Type)
		}
		if got[i].Name != want[i].Name {
			t.Errorf("%s[%d]: name is %q in Go, %q in Solidity", what, i, got[i].Name, want[i].Name)
		}
		if got[i].Indexed != want[i].Indexed {
			t.Errorf("%s[%d] (%s): indexed is %v in Go, %v in Solidity",
				what, i, want[i].Name, got[i].Indexed, want[i].Indexed)
		}
	}
}
