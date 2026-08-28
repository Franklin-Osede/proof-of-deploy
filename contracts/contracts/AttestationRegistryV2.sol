// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title AttestationRegistryV2
/// @notice Tamper-evident public log of workload-state attestations, keyed by a
///         cluster-aware workload identity.
///
/// @dev What changed from v1, and why:
///
///      1. The key is a WORKLOAD id, not SHA-256("namespace/name"). v1 had no
///         notion of a cluster, so the same namespace/name in two clusters
///         sharing a registry occupied one slot and each overwrote the other.
///         The id is computed off-chain over an injective encoding of
///         (clusterID, apiVersion, kind, namespace, name).
///
///      2. Records carry an `incarnation`: which specific Kubernetes object was
///         observed, as opposed to what was configured. It is bound by the
///         off-chain signature, not merely stored, so a compromised publisher
///         cannot pair a valid signature with a different incarnation.
///
///      3. The event is self-sufficient. v1 emitted no signature, so once a
///         record was overwritten the previous attestation was unverifiable
///         forever. Storage is still latest-only; history lives in logs.
///
/// @dev Trust model, unchanged from v1: the meaning of an attestation comes from
///      the off-chain signature, NOT from this contract. It restricts writes to
///      one configured publisher so third parties cannot pollute a slot, but a
///      verifier MUST still check the signature against a public key it trusts
///      from somewhere else. A compromised publisher key can still write a
///      validly-signed attestation of a malicious cluster state.
///
///      This contract deliberately does not interpret what it stores. It cannot
///      verify a signature, does not know the trusted public key, and does not
///      decide which protocol versions exist -- that last one is the verifier's
///      job, and putting it here would mean a protocol upgrade required a
///      contract upgrade.
///
///      TESTNET DEMO. Never mainnet, never real funds.
contract AttestationRegistryV2 {
    struct Attestation {
        bytes32 configHash;
        bytes32 signerFingerprint;
        /// @dev Fixed-width form of the observed object's Kubernetes UID.
        ///      Zero means no incarnation was bound: legitimate in principle,
        ///      but a live-cluster attestation should always set it, so a
        ///      verifier should treat zero as a weaker result rather than
        ///      equivalent. Not rejected here, because deciding that is
        ///      interpretation.
        bytes32 incarnation;
        bytes signature;
        // Packed into one slot: 8 + 2 + 1 bytes.
        uint64 blockTimestamp;
        uint16 hashVersion;
        bool exists;
    }

    /// @notice The only address permitted to publish. Set once at deploy time.
    /// @dev Immutable on purpose. A rotatable owner would add exactly the
    ///      administrative power this design avoids, and would cost the
    ///      property that the contract is small enough to audit at a glance.
    ///      Loss or compromise means deploying a new contract and
    ///      redistributing a versioned address.
    address public immutable publisher;

    /// @dev workloadId => latest attestation. workloadId is computed off-chain
    ///      as SHA-256 over an injective encoding of the workload identity,
    ///      including the cluster.
    mapping(bytes32 => Attestation) private latest;

    /// @notice Emitted on every publish, carrying everything needed to verify
    ///         the attestation later.
    /// @dev Includes the signature precisely because storage is latest-only:
    ///      without it, an overwritten attestation could never be checked
    ///      again. Note the limits: contracts cannot read logs, so this serves
    ///      off-chain verifiers only; a historical verifier needs an RPC with
    ///      unpruned logs or an indexer; and reorg and finality still apply.
    ///      Reconstructible is not the same as guaranteed available.
    ///
    ///      Only workloadId and hashVersion are indexed. A cluster topic was
    ///      considered and rejected: the contract cannot check it against
    ///      workloadId, so a wrong value would mislead indexers while being
    ///      covered by nothing.
    event AttestationPublished(
        bytes32 indexed workloadId,
        uint16 indexed hashVersion,
        bytes32 configHash,
        bytes32 incarnation,
        bytes32 signerFingerprint,
        bytes signature,
        uint64 blockTimestamp
    );

    error NotPublisher();
    /// @dev Version 0 is what an unset struct reads back as, so it can never be
    ///      a valid protocol version. Rejecting it keeps "never published"
    ///      distinguishable from "published under version 0".
    error InvalidHashVersion();
    /// @dev Well-formedness, not semantics: a zero-length signature can never
    ///      verify, so storing one only wastes a slot and misleads a reader.
    error EmptySignature();

    constructor(address _publisher) {
        require(_publisher != address(0), "publisher is zero address");
        publisher = _publisher;
    }

    modifier onlyPublisher() {
        if (msg.sender != publisher) revert NotPublisher();
        _;
    }

    /// @notice Record (or overwrite) the latest attestation for a workload.
    /// @param workloadId  SHA-256 over the injective encoding of the workload
    ///                    identity, including cluster.
    /// @param hashVersion Off-chain hash protocol that produced configHash.
    /// @param incarnation Fixed-width form of the observed object's UID, or
    ///                    zero if none was bound.
    function publish(
        bytes32 workloadId,
        uint16 hashVersion,
        bytes32 configHash,
        bytes32 incarnation,
        bytes calldata signature,
        bytes32 signerFingerprint
    ) external onlyPublisher {
        if (hashVersion == 0) revert InvalidHashVersion();
        if (signature.length == 0) revert EmptySignature();

        uint64 ts = uint64(block.timestamp);
        latest[workloadId] = Attestation({
            configHash: configHash,
            signerFingerprint: signerFingerprint,
            incarnation: incarnation,
            signature: signature,
            blockTimestamp: ts,
            hashVersion: hashVersion,
            exists: true
        });

        emit AttestationPublished(
            workloadId,
            hashVersion,
            configHash,
            incarnation,
            signerFingerprint,
            signature,
            ts
        );
    }

    /// @notice Read the latest attestation. `exists` is false if none recorded,
    ///         in which case every other field is zero.
    function getLatest(bytes32 workloadId)
        external
        view
        returns (
            bytes32 configHash,
            bytes memory signature,
            bytes32 signerFingerprint,
            bytes32 incarnation,
            uint64 blockTimestamp,
            uint16 hashVersion,
            bool exists
        )
    {
        Attestation storage a = latest[workloadId];
        return (
            a.configHash,
            a.signature,
            a.signerFingerprint,
            a.incarnation,
            a.blockTimestamp,
            a.hashVersion,
            a.exists
        );
    }
}
