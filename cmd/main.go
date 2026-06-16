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

package main

import (
	"flag"
	"math/big"
	"os"
	"strconv"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
	"github.com/franklin1014/proof-of-deploy/internal/chain"
	"github.com/franklin1014/proof-of-deploy/internal/controller"
	"github.com/franklin1014/proof-of-deploy/internal/publisher"
	"github.com/franklin1014/proof-of-deploy/internal/signer"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		kmsKeyID             string
		ethRPCURL            string
		contractAddr         string
		chainID              int64
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metrics endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election so only one replica publishes attestations.")
	flag.StringVar(&kmsKeyID, "kms-key-id", os.Getenv("KMS_KEY_ID"),
		"AWS KMS key id, ARN, or alias used to sign attestations (spec ECC_NIST_P256).")
	flag.StringVar(&ethRPCURL, "eth-rpc-url", os.Getenv("ETH_RPC_URL"),
		"Testnet JSON-RPC endpoint (Base Sepolia or Polygon Amoy). NEVER point this at mainnet.")
	flag.StringVar(&contractAddr, "contract-address", os.Getenv("CONTRACT_ADDRESS"),
		"Deployed AttestationRegistry contract address.")
	flag.Int64Var(&chainID, "chain-id", envInt64("CHAIN_ID", 84532),
		"EVM chain id. Default 84532 (Base Sepolia). Polygon Amoy is 80002.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if kmsKeyID == "" || ethRPCURL == "" || contractAddr == "" {
		setupLog.Error(nil, "missing required configuration",
			"kms-key-id", kmsKeyID != "", "eth-rpc-url", ethRPCURL != "", "contract-address", contractAddr != "")
		os.Exit(1)
	}
	// The Ethereum account that pays testnet gas. This is unrelated to the KMS
	// attestation key. It MUST be a throwaway testnet key funded from a faucet.
	ethPrivateKey := os.Getenv("ETH_PRIVATE_KEY")
	if ethPrivateKey == "" {
		setupLog.Error(nil, "ETH_PRIVATE_KEY (testnet gas key) is required")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "proof-of-deploy.proof-of-deploy.dev",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	kmsSigner, err := signer.NewKMSSigner(ctx, kmsKeyID)
	if err != nil {
		setupLog.Error(err, "unable to initialize KMS signer")
		os.Exit(1)
	}
	chainWriter, err := chain.NewWriter(ctx, ethRPCURL, contractAddr, ethPrivateKey, big.NewInt(chainID))
	if err != nil {
		setupLog.Error(err, "unable to initialize chain writer")
		os.Exit(1)
	}

	pub := publisher.New(kmsSigner, chainWriter, ctrl.Log)
	if err := mgr.Add(pub); err != nil {
		setupLog.Error(err, "unable to register publisher runnable")
		os.Exit(1)
	}

	if err := (&controller.DeploymentReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Publisher: pub,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Deployment")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Log the signer's public-key fingerprint at startup so operators can
	// confirm which key is in use without exposing key material.
	setupLog.Info("starting proof-of-deploy operator",
		"chainID", chainID, "contract", contractAddr, "kmsKeyID", kmsKeyID,
		"signerFingerprint", attest.PublicKeyFingerprint(kmsSigner.PublicKeyDER()))
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
