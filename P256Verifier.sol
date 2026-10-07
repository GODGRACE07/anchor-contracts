// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library P256Verifier {
    address constant VERIFIER = 0x0000000000000000000000000000000000000100;

    function verify(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bool) {
        bytes memory input = abi.encodePacked(
            messageHash,
            r,
            s,
            pubKeyX,
            pubKeyY
        );

        (bool success, bytes memory result) = VERIFIER.staticcall(input);

        if (!success || result.length == 0) {
            return false;
        }

        return abi.decode(result, (uint256)) == 1;
    }
}
