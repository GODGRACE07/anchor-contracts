// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./P256Verifier.sol";

library WebAuthnVerifier {
    struct WebAuthnProof {
        bytes authenticatorData;
        string clientDataJSONPrefix;
        string clientDataJSONSuffix;
        bytes32 sigR;
        bytes32 sigS;
    }

    function verify(
        WebAuthnProof memory proof,
        bytes32 expectedChallenge,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bool) {
        string memory challengeB64 = _base64UrlEncode(abi.encodePacked(expectedChallenge));

        bytes memory clientDataJSON = abi.encodePacked(
            proof.clientDataJSONPrefix,
            challengeB64,
            proof.clientDataJSONSuffix
        );

        bytes32 clientDataHash = sha256(clientDataJSON);
        bytes32 messageHash = sha256(
            abi.encodePacked(proof.authenticatorData, clientDataHash)
        );

        return P256Verifier.verify(
            messageHash,
            proof.sigR,
            proof.sigS,
            pubKeyX,
            pubKeyY
        );
    }

    function _base64UrlEncode(bytes memory data)
        internal
        pure
        returns (string memory)
    {
        bytes memory alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        if (data.length == 0) return "";

        uint256 encodedLen = 4 * ((data.length + 2) / 3);
        bytes memory result = new bytes(encodedLen);
        uint256 resultPtr = 0;

        for (uint256 i = 0; i < data.length; i += 3) {
            uint256 chunk = uint256(uint8(data[i])) << 16;

            if (i + 1 < data.length) {
                chunk |= uint256(uint8(data[i + 1])) << 8;
            }

            if (i + 2 < data.length) {
                chunk |= uint256(uint8(data[i + 2]));
            }

            result[resultPtr++] = alphabet[(chunk >> 18) & 0x3F];
            result[resultPtr++] = alphabet[(chunk >> 12) & 0x3F];

            if (i + 1 < data.length) {
                result[resultPtr++] = alphabet[(chunk >> 6) & 0x3F];
            }

            if (i + 2 < data.length) {
                result[resultPtr++] = alphabet[chunk & 0x3F];
            }
        }

        uint256 actualLen = (data.length * 4 + 2) / 3;
        bytes memory trimmed = new bytes(actualLen);

        for (uint256 i = 0; i < actualLen; i++) {
            trimmed[i] = result[i];
        }

        return string(trimmed);
    }
}
