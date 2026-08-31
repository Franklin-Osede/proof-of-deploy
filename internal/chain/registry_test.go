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
	"regexp"
	"strings"
	"testing"
)

// artifacts are where Hardhat writes the compiled contracts. They are
// gitignored, so these checks skip when the contracts have not been built. CI
// compiles them first, which is what makes the check real rather than
// decorative.
//
// Every ABI constant the Go side declares must appear here. A new contract
// whose ABI is hand-maintained but unguarded would reintroduce exactly the
// drift this test exists to prevent.
var abiUnderTest = []struct {
	name         string
	goABI        string
	artifactPath string
	required     []string
}{
	{
		name:         "AttestationRegistry",
		goABI:        RegistryABI,
		artifactPath: "../../contracts/artifacts/contracts/AttestationRegistry.sol/AttestationRegistry.json",
		required:     []string{"function publish", "function getLatest", "event AttestationPublished"},
	},
	{
		name:         "AttestationRegistryV2",
		goABI:        RegistryV2ABI,
		artifactPath: "../../contracts/artifacts/contracts/AttestationRegistryV2.sol/AttestationRegistryV2.json",
		required:     []string{"function publish", "function getLatest", "event AttestationPublished"},
	},
}

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
	for _, tc := range abiUnderTest {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Clean(tc.artifactPath))
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
			got := index(t, []byte(tc.goABI), "Go")

			// Every entry the Go client declares must match Solidity exactly.
			// The Go side may legitimately omit entries it never calls, so the
			// comparison is one-directional -- but a mismatch on anything
			// declared is a bug.
			for key, g := range got {
				w, ok := want[key]
				if !ok {
					t.Errorf("%s is declared in Go but does not exist in %s", key, tc.name)
					continue
				}
				if g.StateMutability != w.StateMutability {
					t.Errorf("%s: stateMutability is %q in Go, %q in Solidity", key, g.StateMutability, w.StateMutability)
				}
				compareParams(t, key+" inputs", g.Inputs, w.Inputs)
				compareParams(t, key+" outputs", g.Outputs, w.Outputs)
			}

			// The entries the operator and CLI depend on must be present, so a
			// mistyped key cannot turn the check into an empty loop.
			for _, required := range tc.required {
				if _, ok := got[required]; !ok {
					t.Errorf("the Go ABI for %s no longer declares %s", tc.name, required)
				}
			}
		})
	}
}

// TestEveryABIConstantIsGuarded fails if a Go ABI constant exists that
// abiUnderTest does not cover.
//
// It reads the package source rather than carrying a hand-written list,
// because a hand-written list is exactly the thing that goes stale: adding a
// third contract would leave its ABI silently outside the drift check while
// this test kept passing.
func TestEveryABIConstantIsGuarded(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^const\s+(\w*ABI)\s*=`)

	found := map[string]string{} // constant name -> file
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range decl.FindAllStringSubmatch(string(src), -1) {
			found[m[1]] = e.Name()
		}
	}
	if len(found) == 0 {
		t.Fatal("found no ABI constants; the detection regexp has gone stale")
	}

	// Map each guarded case back to the constant it holds by identity, so a
	// renamed constant cannot quietly satisfy the check.
	guarded := map[string]bool{}
	for _, tc := range abiUnderTest {
		for name, value := range map[string]string{
			"RegistryABI":   RegistryABI,
			"RegistryV2ABI": RegistryV2ABI,
		} {
			if tc.goABI == value {
				guarded[name] = true
			}
		}
	}
	for name, file := range found {
		if !guarded[name] {
			t.Errorf("%s (declared in %s) is not covered by abiUnderTest, so nothing checks it against the contract", name, file)
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
