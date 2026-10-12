// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice P-256 / secp256r1 signature verification using Monad's
/// EIP-7951 precompile.
library P256Verifier {
    address internal constant VERIFIER = address(0x0100);

    /// @notice Verify a P-256 ECDSA signature.
    /// @dev The precompile accepts exactly 160 bytes:
    /// hash || r || s || qx || qy.
    /// It returns a 32-byte integer equal to 1 on success.
    /// Invalid signatures may return empty data.
    function verify(bytes32 messageHash, bytes32 r, bytes32 s, bytes32 pubKeyX, bytes32 pubKeyY)
        internal
        view
        returns (bool)
    {
        bytes memory input = abi.encodePacked(messageHash, r, s, pubKeyX, pubKeyY);

        if (input.length != 160) {
            return false;
        }

        (bool success, bytes memory result) = VERIFIER.staticcall(input);

        if (!success || result.length != 32) {
            return false;
        }

        uint256 verified;
        assembly ("memory-safe") {
            verified := mload(add(result, 0x20))
        }

        return verified == 1;
    }
}
