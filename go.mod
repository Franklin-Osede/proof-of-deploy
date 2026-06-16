module github.com/franklin1014/proof-of-deploy

go 1.22.0

// NOTE: run `go mod tidy` to populate go.sum and indirect dependencies.
// The versions below are the intended direct dependencies for the MVP.
require (
	github.com/aws/aws-sdk-go-v2/config v1.27.27
	github.com/aws/aws-sdk-go-v2/service/kms v1.35.3
	github.com/ethereum/go-ethereum v1.14.7
	github.com/spf13/cobra v1.8.1
	k8s.io/api v0.30.3
	k8s.io/apimachinery v0.30.3
	k8s.io/client-go v0.30.3
	sigs.k8s.io/controller-runtime v0.18.4
)
