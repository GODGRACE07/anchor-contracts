// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./P256Verifier.sol";
import "./WebAuthnVerifier.sol";

contract IdentityRegistry {
    struct Identity {
        address owner;
        bytes32 pubKeyX;
        bytes32 pubKeyY;
        string displayName;
        uint64 registeredAt;
        bool active;
    }

    mapping(bytes32 => Identity) public identities;

    event IdentityRegistered(
        bytes32 indexed identityId,
        address indexed owner,
        string displayName
    );

    event IdentityDeactivated(bytes32 indexed identityId);

    function _identityId(
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pubKeyX, pubKeyY));
    }

    function registrationMessageHash(
        address caller
    ) public pure returns (bytes32) {
        return sha256(abi.encodePacked("Anchor:register:", caller));
    }

    /// @notice Registers using a real hardware passkey (Face ID,
    ///         fingerprint, security key) via the browser's WebAuthn API.
    function registerWithPasskey(
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        WebAuthnVerifier.WebAuthnProof calldata proof,
        string calldata displayName
    ) external returns (bytes32) {
        bytes32 id = _identityId(pubKeyX, pubKeyY);

        require(
            identities[id].registeredAt == 0,
            "Identity already registered"
        );

        bytes32 proofMessage = registrationMessageHash(msg.sender);

        require(
            WebAuthnVerifier.verify(
                proof,
                proofMessage,
                pubKeyX,
                pubKeyY
            ),
            "Invalid passkey signature"
        );

        identities[id] = Identity({
            owner: msg.sender,
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            displayName: displayName,
            registeredAt: uint64(block.timestamp),
            active: true
        });

        emit IdentityRegistered(id, msg.sender, displayName);

        return id;
    }

    /// @notice Registers using a raw P256 signature directly (Foundry
    ///         tests / non-browser integrations).
    function register(
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        bytes32 sigR,
        bytes32 sigS,
        string calldata displayName
    ) external returns (bytes32) {
        bytes32 id = _identityId(pubKeyX, pubKeyY);

        require(
            identities[id].registeredAt == 0,
            "Identity already registered"
        );

        bytes32 proofMessage = registrationMessageHash(msg.sender);

        require(
            P256Verifier.verify(
                proofMessage,
                sigR,
                sigS,
                pubKeyX,
                pubKeyY
            ),
            "Invalid proof of possession"
        );

        identities[id] = Identity({
            owner: msg.sender,
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            displayName: displayName,
            registeredAt: uint64(block.timestamp),
            active: true
        });

        emit IdentityRegistered(id, msg.sender, displayName);

        return id;
    }

    function deactivate(bytes32 identityId) external {
        Identity storage idy = identities[identityId];

        require(
            idy.owner == msg.sender,
            "Not your identity"
        );

        idy.active = false;

        emit IdentityDeactivated(identityId);
    }

    function getIdentity(
        bytes32 identityId
    ) external view returns (Identity memory) {
        return identities[identityId];
    }
}
