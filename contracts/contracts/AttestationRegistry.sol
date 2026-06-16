// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title AttestationRegistry
/// @notice Minimal, tamper-evident public log of Deployment-state attestations.
///         For each Deployment identifier it stores the latest config hash, the
///         KMS signature over that hash, the signer's public-key fingerprint,
///         and the block timestamp at which it was recorded.
///
/// @dev Trust model: the meaning of an attestation comes from the off-chain
///      KMS signature, NOT from this contract. The contract restricts writes to
///      a single configured publisher so third parties cannot pollute the
///      "latest" slot, but a verifier MUST still check the signature against a
///      trusted public key. A compromised publisher key can still write a
///      validly-signed attestation of a malicious cluster state — that is out
///      of scope (see project README "Trust boundary"). This is a TESTNET demo
///      contract; a production deployment would batch writes and likely store
///      append-only history rather than only the latest record.
contract AttestationRegistry {
    struct Attestation {
        bytes32 configHash;
        bytes signature;
        bytes32 signerFingerprint;
        uint64 blockTimestamp;
        bool exists;
    }

    /// @notice The only address permitted to publish. Set once at deploy time.
    address public immutable publisher;

    /// @dev deploymentId => latest attestation. deploymentId is computed
    ///      off-chain as SHA-256("namespace/name").
    mapping(bytes32 => Attestation) private latest;

    event AttestationPublished(
        bytes32 indexed deploymentId,
        bytes32 configHash,
        bytes32 signerFingerprint,
        uint64 blockTimestamp
    );

    error NotPublisher();

    constructor(address _publisher) {
        require(_publisher != address(0), "publisher is zero address");
        publisher = _publisher;
    }

    modifier onlyPublisher() {
        if (msg.sender != publisher) revert NotPublisher();
        _;
    }

    /// @notice Record (or overwrite) the latest attestation for a Deployment.
    function publish(
        bytes32 deploymentId,
        bytes32 configHash,
        bytes calldata signature,
        bytes32 signerFingerprint
    ) external onlyPublisher {
        uint64 ts = uint64(block.timestamp);
        latest[deploymentId] = Attestation({
            configHash: configHash,
            signature: signature,
            signerFingerprint: signerFingerprint,
            blockTimestamp: ts,
            exists: true
        });
        emit AttestationPublished(deploymentId, configHash, signerFingerprint, ts);
    }

    /// @notice Read the latest attestation. `exists` is false if none recorded.
    function getLatest(bytes32 deploymentId)
        external
        view
        returns (
            bytes32 configHash,
            bytes memory signature,
            bytes32 signerFingerprint,
            uint64 blockTimestamp,
            bool exists
        )
    {
        Attestation storage a = latest[deploymentId];
        return (a.configHash, a.signature, a.signerFingerprint, a.blockTimestamp, a.exists);
    }
}
