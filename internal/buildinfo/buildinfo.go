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

// Package buildinfo reports which build of proof-of-deploy is running.
//
// This matters more here than in most projects. The config hash is a wire
// format: a verifier that disagrees with the operator produces a FAIL that
// looks like tampering. When that happens the first question is "which builds
// are these", and without an answer the second question is unanswerable.
package buildinfo

import (
	"fmt"
	"runtime/debug"
)

// Set via -ldflags at build time. See the LDFLAGS variable in the Makefile.
//
// The defaults are what an un-stamped build reports, and they are deliberately
// not something that could be mistaken for a release.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// revision falls back to the VCS stamp the Go toolchain embeds automatically,
// so `go install`-ed and `go run` builds still identify themselves even though
// nothing passed -ldflags. Returns Commit unchanged when it was stamped.
func revision() string {
	if Commit != "" {
		return Commit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return ""
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// String renders the full build identity for --version output.
func String() string {
	s := Version
	if rev := revision(); rev != "" {
		s += " (" + rev
		if Date != "" {
			s += ", built " + Date
		}
		s += ")"
	} else if Date != "" {
		s += " (built " + Date + ")"
	}
	return s
}

// Print writes the build identity followed by a newline, for a --version flag.
func Print(name string) {
	fmt.Printf("%s %s\n", name, String())
}
