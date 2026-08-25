# proof-of-deploy — Makefile
# Trimmed from the standard kubebuilder v4 scaffold. There is no CRD in the MVP,
# so manifests/CRD targets are intentionally omitted.

IMG ?= proof-of-deploy:latest

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
	cd contracts && npm install && npm run compile

.PHONY: contracts-test
contracts-test: ## Run the Hardhat contract tests.
	cd contracts && npm install && npm test

##@ Build
.PHONY: build
build: vet ## Build manager and verify CLI binaries.
	go build -o bin/manager ./cmd
	go build -o bin/pod-verify ./cmd/verify

.PHONY: run
run: vet ## Run the operator against the cluster in ~/.kube/config.
	go run ./cmd

.PHONY: docker-build
docker-build: ## Build the operator container image.
	docker build -t ${IMG} .

##@ Deployment
.PHONY: deploy
deploy: ## Deploy the operator using kustomize (config/default).
	kubectl apply -k config/default

.PHONY: undeploy
undeploy: ## Remove the operator.
	kubectl delete -k config/default
