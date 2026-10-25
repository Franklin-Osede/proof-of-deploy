// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title ImpostorRegistry
/// @notice TEST FIXTURE ONLY. Never deploy it anywhere that matters.
/// @dev Copies the outside of AttestationRegistryV2 -- the same publisher()
///      getter and the same getLatest() shape -- and reports a record for every
///      workload. It is what someone would deploy to make a verifier or the
///      operator trust an answer they chose, and it answers every interface
///      call the real registry answers. Only comparing the deployed code with
///      the pinned runtime tells the two apart, which is what the Go
///      validation test proves.
contract ImpostorRegistry {
    address public immutable publisher;

    constructor(address _publisher) {
        publisher = _publisher;
    }

    function getLatest(bytes32)
        external
        pure
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
        return (bytes32(0), hex"00", bytes32(0), bytes32(0), 0, 2, true);
    }
}
