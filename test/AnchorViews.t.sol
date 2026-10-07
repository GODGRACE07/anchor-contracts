// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/AnchorViews.sol";
import "../src/AuthConfigManager.sol";
import "../src/IdentityRegistry.sol";

contract AnchorViewsTest is Test {
    IdentityRegistry registry;
    AuthConfigManager manager;
    AnchorViews views;

    bytes32 constant OWNER_PUB_X =
        0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

    bytes32 constant OWNER_PUB_Y =
        0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

    bytes32 identityId;

    function setUp() public {
        registry = new IdentityRegistry();
        manager = new AuthConfigManager(address(registry));
        views = new AnchorViews(address(registry), address(manager));

        identityId = registry.register(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            0x6dff0fe8309f2454e192031173bc6bce2b4bb050ee93fd096833ffd132cba8fa,
            0x5363fcfd857e1b31dd6e1de820b8dd9c0cfa753260831933448db8438a04bdf0,
            "Owner"
        );

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

    function testIsInitializedReflectsRealState() public view {
        assertTrue(views.isInitialized(address(this)));
        assertFalse(views.isInitialized(address(0xdead)));
    }

    function testNeedsAttentionFalseWithNoPending() public view {
        assertFalse(views.needsAttention(address(this)));
    }

    function testAccountSummaryReflectsRealCrossContractState()
        public
        view
    {
        AnchorViews.AccountSummary memory summary =
            views.getAccountSummary(address(this));

        assertEq(summary.configVersion, 1);
        assertEq(summary.authenticators.length, 1);
        assertEq(summary.signingThreshold, 1);
        assertEq(summary.reconfigThreshold, 1);
        assertFalse(summary.hasPending);

        assertEq(
            summary.authenticators[0].displayName,
            "Owner"
        );

        assertEq(
            summary.authenticators[0].owner,
            address(this)
        );

        assertTrue(summary.authenticators[0].active);
    }

    function testAccountSummaryShowsPendingReconfigDetails()
        public
    {
        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        AuthConfigManager.AuthProof[] memory proofs =
            new AuthConfigManager.AuthProof[](1);

        proofs[0] = AuthConfigManager.AuthProof({
            authenticatorId: 1,
            sigR:
                0x4fd81fdc42ffb20886e2c76fbb97082fb018f858687d80d5eac2857057363e01,
            sigS:
                0x4eb0af2b0c1747ba941f53137d70e6534178820e14a22aed3e1c51a82fc48c37
        });

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
            proofs
        );

        assertTrue(views.needsAttention(address(this)));

        AnchorViews.AccountSummary memory summary =
            views.getAccountSummary(address(this));

        assertTrue(summary.hasPending);
        assertEq(summary.pendingRiskScore, 0);

        assertEq(
            summary.pendingActivatesAt,
            summary.pendingProposedAt +
                manager.RECONFIG_DELAY()
        );
    }
}
