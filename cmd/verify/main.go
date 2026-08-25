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

// Command pod-verify independently checks a live Deployment against its latest
// on-chain attestation. It shares the exact normalization and hashing logic
// used by the operator (internal/attest), so a PASS means: the configuration
// observed in the cluster right now hashes to the value that was signed by the
// expected KMS key and recorded on-chain.
//
// What PASS does NOT mean: it does not prove the cluster was honest when the
// attestation was produced, nor that it is honest now. See README "Trust
// boundary".
package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
	"github.com/franklin1014/proof-of-deploy/internal/chain"
	"github.com/franklin1014/proof-of-deploy/internal/signer"
)

type options struct {
	kubeconfig    string
	kubecontext   string
	namespace     string
	name          string
	rpcURL        string
	contractAddr  string
	publicKeyFile string
	kmsKeyID      string
}

func main() {
	opts := &options{}
	root := &cobra.Command{
		Use:           "pod-verify",
		Short:         "Independently verify a live Deployment against its on-chain attestation",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Recompute a Deployment's config hash and check it against the chain",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd.Context(), opts)
		},
	}
	f := verifyCmd.Flags()
	f.StringVar(&opts.kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to standard loading rules)")
	f.StringVar(&opts.kubecontext, "context", "", "kubeconfig context to use (defaults to the current context)")
	f.StringVarP(&opts.namespace, "namespace", "n", "", "Deployment namespace (required)")
	f.StringVar(&opts.name, "name", "", "Deployment name (required)")
	f.StringVar(&opts.rpcURL, "eth-rpc-url", os.Getenv("ETH_RPC_URL"), "Testnet JSON-RPC endpoint (required)")
	f.StringVar(&opts.contractAddr, "contract-address", os.Getenv("CONTRACT_ADDRESS"), "AttestationRegistry address (required)")
	f.StringVar(&opts.publicKeyFile, "public-key", "", "Path to the signer public key (PEM or DER). If omitted, --kms-key-id is used to fetch it.")
	f.StringVar(&opts.kmsKeyID, "kms-key-id", os.Getenv("KMS_KEY_ID"), "KMS key id/ARN/alias to fetch the public key (used when --public-key is not set)")
	_ = verifyCmd.MarkFlagRequired("namespace")
	_ = verifyCmd.MarkFlagRequired("name")

	root.AddCommand(verifyCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runVerify(ctx context.Context, o *options) error {
	if o.rpcURL == "" || o.contractAddr == "" {
		return fmt.Errorf("--eth-rpc-url and --contract-address are required")
	}

	// 1. Read the live Deployment.
	dep, cluster, err := getDeployment(ctx, o, o.namespace, o.name)
	if err != nil {
		return fmt.Errorf("reading deployment: %w", err)
	}

	// 2. Normalize + hash with the SAME code path the operator uses.
	nd := attest.Normalize(dep)
	localHash, err := attest.ConfigHash(nd)
	if err != nil {
		return fmt.Errorf("hashing deployment: %w", err)
	}
	id := attest.DeploymentID(o.namespace, o.name)

	// 3. Fetch the latest on-chain attestation.
	reader, err := chain.NewReader(ctx, o.rpcURL, o.contractAddr)
	if err != nil {
		return err
	}
	defer reader.Close()
	att, err := reader.LatestAttestation(ctx, id)
	if err != nil {
		return err
	}
	if !att.Exists {
		return fail("no attestation found on-chain for %s/%s", o.namespace, o.name)
	}

	// 4. Hash match.
	if localHash != att.ConfigHash {
		return fail("config hash mismatch\n  live:    %s\n  onchain: %s\n  the running Deployment differs from the attested state",
			attest.MustHex(localHash), attest.MustHex(att.ConfigHash))
	}

	// 5. Confirm the attestation was signed by the expected key.
	pubDER, err := loadPublicKey(ctx, o)
	if err != nil {
		return fmt.Errorf("loading signer public key: %w", err)
	}
	if got := attest.PublicKeyFingerprintBytes(pubDER); got != att.SignerFingerprint {
		return fail("signer fingerprint mismatch\n  expected: %s\n  onchain:  %s\n  attestation was signed by an unexpected key",
			attest.MustHex(got), attest.MustHex(att.SignerFingerprint))
	}

	// 6. Verify the signature over the hash.
	pub, err := attest.ParsePublicKeyDER(pubDER)
	if err != nil {
		return fmt.Errorf("parsing signer public key: %w", err)
	}
	if !attest.VerifyConfigHashSignature(pub, localHash, att.Signature) {
		return fail("signature verification failed for the attested config hash")
	}

	fmt.Printf("PASS  %s/%s\n", o.namespace, o.name)
	fmt.Printf("  cluster:            %s\n", cluster)
	fmt.Printf("  config hash:        %s\n", attest.MustHex(localHash))
	fmt.Printf("  signer fingerprint: %s\n", attest.MustHex(att.SignerFingerprint))
	fmt.Printf("  block timestamp:    %d\n", att.BlockTimestamp)
	fmt.Println("  the live Deployment matches a signature recorded on-chain by the expected key.")
	return nil
}

// failErr lets runVerify return a FAIL with a clear, already-printed reason and
// a non-zero exit code, distinct from operational errors.
type failErr struct{ msg string }

func (e failErr) Error() string { return e.msg }

func fail(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("FAIL  %s\n", msg)
	return failErr{msg: msg}
}

// getDeployment reads the live Deployment and also reports which cluster it was
// read from. Without --context the CLI follows whatever context happens to be
// current, which on a multi-cluster machine can silently verify the wrong
// cluster; returning the endpoint lets the result say what it actually checked.
func getDeployment(ctx context.Context, o *options, namespace, name string) (*appsv1.Deployment, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if o.kubeconfig != "" {
		loadingRules.ExplicitPath = o.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if o.kubecontext != "" {
		overrides.CurrentContext = o.kubecontext
	}
	deferred := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	cfg, err := deferred.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}

	cluster := cfg.Host
	if raw, err := deferred.RawConfig(); err == nil {
		name := o.kubecontext
		if name == "" {
			name = raw.CurrentContext
		}
		if name != "" {
			cluster = fmt.Sprintf("%s (%s)", name, cfg.Host)
		}
	}

	dep, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, cluster, err
	}
	return dep, cluster, nil
}

// loadPublicKey returns the signer's DER SubjectPublicKeyInfo, either from a
// local PEM/DER file or by fetching it from KMS.
func loadPublicKey(ctx context.Context, o *options) ([]byte, error) {
	if o.publicKeyFile != "" {
		raw, err := os.ReadFile(o.publicKeyFile)
		if err != nil {
			return nil, err
		}
		if block, _ := pem.Decode(raw); block != nil {
			return block.Bytes, nil
		}
		return raw, nil // assume DER
	}
	if o.kmsKeyID == "" {
		return nil, fmt.Errorf("provide --public-key or --kms-key-id to obtain the signer key")
	}
	s, err := signer.NewKMSSigner(ctx, o.kmsKeyID)
	if err != nil {
		return nil, err
	}
	return s.PublicKeyDER(), nil
}
