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
.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run unit tests (no cluster required).
	go test ./internal/... -coverprofile cover.out

##@ Build
.PHONY: build
build: fmt vet ## Build manager and verify CLI binaries.
	go build -o bin/manager ./cmd
	go build -o bin/pod-verify ./cmd/verify

.PHONY: run
run: fmt vet ## Run the operator against the cluster in ~/.kube/config.
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
