// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/AuthConfigManager.sol";
import "../src/IdentityRegistry.sol";
import "../src/WebAuthnVerifier.sol";

contract ProposeWithPasskeyTest is Test {
    AuthConfigManager manager;
    IdentityRegistry registry;

    bytes32 constant OWNER_PUB_X = 0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;
    bytes32 constant OWNER_PUB_Y = 0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;
    address constant REAL_ACCOUNT = 0x919A5ba08A3CCfD066a5f7d5b125Bc0eD98CEb66;

    bytes32 identityId;

    function setUp() public {
        registry = new IdentityRegistry();
        manager = new AuthConfigManager(address(registry));

        vm.prank(REAL_ACCOUNT);
        identityId = registry.register(
            OWNER_PUB_X, OWNER_PUB_Y,
            0x30903c14d92281a5a20fc1b1cce1b6d741954c377d360231f08281df968b11e3,
            0x3c543f086b256ee926f65b8b81e3ea66b7bfc4dd28f150cbe3633537c3b9fbfb,
            "Owner"
        );

        AuthConfigManager.Authenticator[] memory auths = new AuthConfigManager.Authenticator[](1);
        auths[0] = AuthConfigManager.Authenticator({
            id: 1, scheme: AuthConfigManager.Scheme.P256_PASSKEY, identityId: identityId
        });
        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        vm.prank(REAL_ACCOUNT);
        manager.initializeConfig(auths, policy, 1, policy, 1);
    }

    function _realProposeProof() internal pure returns (AuthConfigManager.WebAuthnAuthProof[] memory) {
        AuthConfigManager.WebAuthnAuthProof[] memory proofs = new AuthConfigManager.WebAuthnAuthProof[](1);
        proofs[0] = AuthConfigManager.WebAuthnAuthProof({
            authenticatorId: 1,
            proof: WebAuthnVerifier.WebAuthnProof({
                authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000002",
                clientDataJSONPrefix: '{"type":"webauthn.get","challenge":"',
                clientDataJSONSuffix: '","origin":"http://localhost:3000","crossOrigin":false}',
                sigR: 0x6fa3b868e397568028fee88e2f9742ab92f5b7a7b64c604dca3345887ec54aa3,
                sigS: 0x28a03168a49cf7e8a6abc3599bb766420e9ca2980643a8ce0704616e669b5e65
            })
        });
        return proofs;
    }

    function testProposeWithRealWebAuthnSignature() public {
        AuthConfigManager.Authenticator[] memory newAuths = new AuthConfigManager.Authenticator[](1);
        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1, scheme: AuthConfigManager.Scheme.P256_PASSKEY, identityId: identityId
        });
        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        vm.prank(REAL_ACCOUNT);
        manager.proposeReconfigurationWithPasskey(
            abi.encode(
                REAL_ACCOUNT,
                newAuths,
                policy,
                uint8(1),
                policy,
                uint8(1),
                true,
                _realProposeProof()
            )
        );

        AuthConfigManager.PendingReconfig memory pending = manager.getPendingReconfig(REAL_ACCOUNT);
        assertTrue(pending.exists);
    }
}
