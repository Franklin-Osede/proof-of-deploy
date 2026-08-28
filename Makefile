# proof-of-deploy — Makefile
# Trimmed from the standard kubebuilder v4 scaffold. There is no CRD in the MVP,
# so manifests/CRD targets are intentionally omitted.

# VERSION identifies the build. `git describe` gives a real tag once one exists
# and a commit-ish before that; -dirty is deliberate, so a stamped binary can
# never claim to be a clean release when it is not.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
# Overridable so a release build can pass SOURCE_DATE_EPOCH and stay reproducible.
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# IMAGE_TAG is the tag the deployment manifests reference. It must match
# newTag in config/manager/kustomization.yaml, so `make docker-build && make
# deploy` installs the image that was just built rather than whatever `latest`
# happens to be.
IMAGE_TAG ?= v0.1.0-experimental
IMG ?= proof-of-deploy:$(IMAGE_TAG)

MODULE  := github.com/franklin1014/proof-of-deploy
LDFLAGS := -s -w \
  -X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
  -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
  -X $(MODULE)/internal/buildinfo.Date=$(DATE)

# Tool versions
ENVTEST_K8S_VERSION = 1.30.0

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General
.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Development
# NOTE: `fmt` rewrites source files, so it is never a prerequisite of build,
# test, or run — those must not mutate a checkout. CI runs `fmt-check`, which
# fails on a difference instead of silently fixing it.
.PHONY: fmt
fmt: ## Format the source tree in place.
	go fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean (does not modify anything).
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "Not gofmt-clean:"; echo "$$out"; \
		echo; echo "Run 'make fmt' to fix."; exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: vet ## Run all unit tests (no cluster required).
	go test ./... -coverprofile cover.out

##@ Contracts
.PHONY: contracts-compile
contracts-compile: ## Compile the Solidity contracts.
	cd contracts && npm ci && npm run compile

.PHONY: contracts-test
contracts-test: ## Run the Hardhat contract tests.
	cd contracts && npm ci && npm test

##@ Build
.PHONY: build
build: vet ## Build manager and verify CLI binaries.
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/manager ./cmd
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/pod-verify ./cmd/verify

.PHONY: run
run: vet ## Run the operator against the cluster in ~/.kube/config.
	go run ./cmd

.PHONY: docker-build
docker-build: ## Build the operator container image.
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) \
	  -t ${IMG} .

##@ Deployment
.PHONY: deploy
deploy: ## Deploy the operator using kustomize (config/default).
	kubectl apply -k config/default

.PHONY: undeploy
undeploy: ## Remove the operator.
	kubectl delete -k config/default
