// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/AuthConfigManager.sol";
import "../src/IdentityRegistry.sol";
import "../src/P256Verifier.sol";

contract AuthConfigManagerTest is Test {
    AuthConfigManager manager;
    IdentityRegistry registry;

    bytes32 constant OWNER_PUB_X =
        0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

    bytes32 constant OWNER_PUB_Y =
        0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

    bytes32 identityId;

    function setUp() public {
        registry = new IdentityRegistry();
        manager = new AuthConfigManager(address(registry));

        identityId = registry.register(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            0x6dff0fe8309f2454e192031173bc6bce2b4bb050ee93fd096833ffd132cba8fa,
            0x5363fcfd857e1b31dd6e1de820b8dd9c0cfa753260831933448db8438a04bdf0,
            "Owner"
        );
    }

    function _initBasicConfig() internal {
        AuthConfigManager.Authenticator[] memory auths =
            new AuthConfigManager.Authenticator[](1);

        auths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.initializeConfig(
            auths,
            policy,
            1,
            policy,
            1
        );
    }

    function _proposeProof()
        internal
        pure
        returns (AuthConfigManager.AuthProof[] memory)
    {
        AuthConfigManager.AuthProof[] memory proofs =
            new AuthConfigManager.AuthProof[](1);

        proofs[0] = AuthConfigManager.AuthProof({
            authenticatorId: 1,
            sigR: 0x4fd81fdc42ffb20886e2c76fbb97082fb018f858687d80d5eac2857057363e01,
            sigS: 0x4eb0af2b0c1747ba941f53137d70e6534178820e14a22aed3e1c51a82fc48c37
        });

        return proofs;
    }

    function testInitializeConfig() public {
        _initBasicConfig();

        AuthConfigManager.AuthConfig memory cfg =
            manager.getConfig(address(this));

        assertEq(cfg.configVersion, 1);
    }

    function testRawP256IdentityCannotAuthorizeDifferentAccount() public {
        address accountB =
            address(0x000000000000000000000000000000000000b0b0);

        IdentityRegistry registryB =
            new IdentityRegistry();

        AuthConfigManager managerB =
            new AuthConfigManager(address(registryB));

        vm.prank(accountB);

        bytes32 identityB = registryB.register(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            0x31e10dc6dfc5edbff9fdd5fea59a31f315cc5bd5b10d4b6c5f0a0e4016637afc,
            0xbd674a0b3c985efd2e6544b51ab63ac917b571732548fe6be62fb4feca24c087,
            "Account B"
        );

        AuthConfigManager.Authenticator[] memory auths =
            new AuthConfigManager.Authenticator[](1);

        auths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityB
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        // Intentionally initialize Account A with an identity
        // that is actually owned by Account B.
        managerB.initializeConfig(
            auths,
            policy,
            1,
            policy,
            1
        );

        vm.expectRevert(
            "Authenticator identity owner mismatch"
        );

        managerB.proposeReconfiguration(
            address(this),
            AuthConfigManager.ReconfigInput({
                authenticators: auths,
                signingPolicy: policy,
                signingThreshold: 1,
                reconfigPolicy: policy,
                reconfigThreshold: 1,
                isKnownDevicePattern: true
            }),
            _proposeProof()
        );
    }

    function testProposeReconfiguration() public {
        _initBasicConfig();

        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.proposeReconfiguration(
            address(this),
            AuthConfigManager.ReconfigInput({
                authenticators: newAuths,
                signingPolicy: policy,
                signingThreshold: 1,
                reconfigPolicy: policy,
                reconfigThreshold: 1,
                isKnownDevicePattern: true
            }),
            _proposeProof()
        );

        AuthConfigManager.PendingReconfig memory pending =
            manager.getPendingReconfig(address(this));

        assertTrue(pending.exists);
    }

    function testCannotActivateBeforeDelay() public {
        _initBasicConfig();

        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.proposeReconfiguration(
            address(this),
            AuthConfigManager.ReconfigInput({
                authenticators: newAuths,
                signingPolicy: policy,
                signingThreshold: 1,
                reconfigPolicy: policy,
                reconfigThreshold: 1,
                isKnownDevicePattern: true
            }),
            _proposeProof()
        );

        vm.expectRevert("Delay not yet elapsed");
        manager.activateReconfiguration(address(this));
    }

    function testActivatesAfterDelay() public {
        _initBasicConfig();

        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.proposeReconfiguration(
            address(this),
            AuthConfigManager.ReconfigInput({
                authenticators: newAuths,
                signingPolicy: policy,
                signingThreshold: 1,
                reconfigPolicy: policy,
                reconfigThreshold: 1,
                isKnownDevicePattern: true
            }),
            _proposeProof()
        );

        vm.warp(block.timestamp + 24 hours + 1);

        manager.activateReconfiguration(address(this));

        AuthConfigManager.AuthConfig memory cfg =
            manager.getConfig(address(this));

        assertEq(cfg.configVersion, 2);
    }

    function testContestPreventsActivationWithRealSignature() public {
        _initBasicConfig();

        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.proposeReconfiguration(
            address(this),
            AuthConfigManager.ReconfigInput({
                authenticators: newAuths,
                signingPolicy: policy,
                signingThreshold: 1,
                reconfigPolicy: policy,
                reconfigThreshold: 1,
                isKnownDevicePattern: true
            }),
            _proposeProof()
        );

        // Stale nonce-0 signature after propose consumed nonce 0 -- must fail.
        AuthConfigManager.AuthProof memory contestProof =
            AuthConfigManager.AuthProof({
                authenticatorId: 1,
                sigR: 0xf5cea42a97766d9bc6b4556a623e2cb5afb62ac4f9d3dece4c59f888bcdaabae,
                sigS: 0xd7593c4c2d628a9444f5582db816897ec9f1b53bf09fd5bf7da925fe1f993f01
            });

        vm.expectRevert("Invalid contest signature");

        manager.contestReconfiguration(
            address(this),
            contestProof
        );
    }

    function testContestSucceedsWithValidSignatureAtCorrectNonce() public {
        _initBasicConfig();

        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.proposeReconfiguration(
            address(this),
            AuthConfigManager.ReconfigInput({
                authenticators: newAuths,
                signingPolicy: policy,
                signingThreshold: 1,
                reconfigPolicy: policy,
                reconfigThreshold: 1,
                isKnownDevicePattern: true
            }),
            _proposeProof()
        );

        AuthConfigManager.AuthProof memory contestProof =
            AuthConfigManager.AuthProof({
                authenticatorId: 1,
                sigR: 0x687e6a4f95804974bac6eb7d036df05bda033124db38ed05dbae7a9171c2c63a,
                sigS: 0x35cffc66d88598f3e8038d03ed22febcdb54eef884f6c2befe8208354672c8ee
            });

        manager.contestReconfiguration(
            address(this),
            contestProof
        );

        AuthConfigManager.PendingReconfig memory pending =
            manager.getPendingReconfig(address(this));

        assertFalse(pending.exists);

        vm.warp(block.timestamp + 24 hours + 1);

        vm.expectRevert("No pending reconfiguration");

        manager.activateReconfiguration(address(this));

        AuthConfigManager.AuthConfig memory cfg =
            manager.getConfig(address(this));

        assertEq(cfg.configVersion, 1);
    }
}

contract AuthConfigManagerPolicyValidationTest is Test {
    IdentityRegistry internal registry;
    AuthConfigManager internal manager;

    function setUp() public {
        registry = new IdentityRegistry();
        manager = new AuthConfigManager(address(registry));
    }

    function _auth(
        uint8 id,
        bytes32 identityId
    ) internal pure returns (AuthConfigManager.Authenticator memory) {
        return AuthConfigManager.Authenticator({
            id: id,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });
    }

    function _singleProof(
        uint8 id
    ) internal pure returns (AuthConfigManager.AuthProof[] memory proofs) {
        proofs = new AuthConfigManager.AuthProof[](1);
        proofs[0] = AuthConfigManager.AuthProof({
            authenticatorId: id,
            sigR: bytes32(0),
            sigS: bytes32(0)
        });
    }

    function testRejectsDuplicateAuthenticatorId() public {
        AuthConfigManager.Authenticator[] memory authenticators =
            new AuthConfigManager.Authenticator[](2);

        authenticators[0] = _auth(1, bytes32(uint256(1)));
        authenticators[1] = _auth(1, bytes32(uint256(2)));

        uint8[] memory signingPolicy = new uint8[](1);
        signingPolicy[0] = 1;

        uint8[] memory reconfigPolicy = new uint8[](1);
        reconfigPolicy[0] = 1;

        vm.expectRevert("Duplicate authenticator id");

        manager.initializeConfig(
            authenticators,
            signingPolicy,
            1,
            reconfigPolicy,
            1
        );
    }

    function testRejectsDuplicateAuthenticatorIdentity() public {
        bytes32 identityId = bytes32(uint256(123));

        AuthConfigManager.Authenticator[] memory authenticators =
            new AuthConfigManager.Authenticator[](2);

        authenticators[0] = _auth(1, identityId);
        authenticators[1] = _auth(2, identityId);

        uint8[] memory signingPolicy = new uint8[](2);
        signingPolicy[0] = 1;
        signingPolicy[1] = 2;

        uint8[] memory reconfigPolicy = new uint8[](2);
        reconfigPolicy[0] = 1;
        reconfigPolicy[1] = 2;

        vm.expectRevert("Duplicate authenticator identity");

        manager.initializeConfig(
            authenticators,
            signingPolicy,
            2,
            reconfigPolicy,
            2
        );
    }

    function testRejectsDuplicateSigningPolicyId() public {
        AuthConfigManager.Authenticator[] memory authenticators =
            new AuthConfigManager.Authenticator[](2);

        authenticators[0] = _auth(1, bytes32(uint256(1)));
        authenticators[1] = _auth(2, bytes32(uint256(2)));

        uint8[] memory signingPolicy = new uint8[](2);
        signingPolicy[0] = 1;
        signingPolicy[1] = 1;

        uint8[] memory reconfigPolicy = new uint8[](1);
        reconfigPolicy[0] = 1;

        vm.expectRevert("Duplicate signing policy id");

        manager.initializeConfig(
            authenticators,
            signingPolicy,
            2,
            reconfigPolicy,
            1
        );
    }

    function testRejectsDuplicateReconfigPolicyId() public {
        AuthConfigManager.Authenticator[] memory authenticators =
            new AuthConfigManager.Authenticator[](2);

        authenticators[0] = _auth(1, bytes32(uint256(1)));
        authenticators[1] = _auth(2, bytes32(uint256(2)));

        uint8[] memory signingPolicy = new uint8[](1);
        signingPolicy[0] = 1;

        uint8[] memory reconfigPolicy = new uint8[](2);
        reconfigPolicy[0] = 1;
        reconfigPolicy[1] = 1;

        vm.expectRevert("Duplicate reconfig policy id");

        manager.initializeConfig(
            authenticators,
            signingPolicy,
            1,
            reconfigPolicy,
            2
        );
    }

    function testRejectsUnknownSigningPolicyAuthenticator() public {
        AuthConfigManager.Authenticator[] memory authenticators =
            new AuthConfigManager.Authenticator[](1);

        authenticators[0] = _auth(1, bytes32(uint256(1)));

        uint8[] memory signingPolicy = new uint8[](1);
        signingPolicy[0] = 99;

        uint8[] memory reconfigPolicy = new uint8[](1);
        reconfigPolicy[0] = 1;

        vm.expectRevert("Signing policy authenticator not found");

        manager.initializeConfig(
            authenticators,
            signingPolicy,
            1,
            reconfigPolicy,
            1
        );
    }

    function testRejectsUnknownReconfigPolicyAuthenticator() public {
        AuthConfigManager.Authenticator[] memory authenticators =
            new AuthConfigManager.Authenticator[](1);

        authenticators[0] = _auth(1, bytes32(uint256(1)));

        uint8[] memory signingPolicy = new uint8[](1);
        signingPolicy[0] = 1;

        uint8[] memory reconfigPolicy = new uint8[](1);
        reconfigPolicy[0] = 99;

        vm.expectRevert("Reconfig policy authenticator not found");

        manager.initializeConfig(
            authenticators,
            signingPolicy,
            1,
            reconfigPolicy,
            1
        );
    }
}
