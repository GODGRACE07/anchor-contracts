// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";
import "../src/WebAuthnVerifier.sol";

contract RegisterWithPasskeyTest is Test {
    IdentityRegistry registry;

    bytes32 constant OWNER_PUB_X =
        0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

    bytes32 constant OWNER_PUB_Y =
        0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

    address constant REAL_ACCOUNT =
        0x919A5ba08A3CCfD066a5f7d5b125Bc0eD98CEb66;

    function setUp() public {
        registry = new IdentityRegistry();
    }

    function _realProof()
        internal
        pure
        returns (WebAuthnVerifier.WebAuthnProof memory)
    {
        return WebAuthnVerifier.WebAuthnProof({
            authenticatorData:
                hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001",

            clientDataJSONPrefix:
                '{"type":"webauthn.get","challenge":"',

            clientDataJSONSuffix:
                '","origin":"http://localhost:3000","crossOrigin":false}',

            sigR:
                0x6a6f465a9de74f33b96c4dcea4531ea16bf03abce7521d93202cb1bc4b38f4ff,

            sigS:
                0x79156e140a8d7be0fb1152bc143244850279766a3e8eff05a91a56313a586e82
        });
    }

    function testRegisterWithRealWebAuthnSignature() public {
        vm.prank(REAL_ACCOUNT);

        bytes32 id = registry.registerWithPasskey(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            _realProof(),
            "Grace's Passkey"
        );

        IdentityRegistry.Identity memory idy =
            registry.getIdentity(id);

        assertEq(idy.owner, REAL_ACCOUNT);
        assertEq(idy.pubKeyX, OWNER_PUB_X);
        assertTrue(idy.active);
        assertEq(idy.displayName, "Grace's Passkey");
    }

    function testRejectsWrongChallenge() public {
        vm.prank(address(0xBAD));

        vm.expectRevert("Invalid passkey signature");

        registry.registerWithPasskey(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            _realProof(),
            "Attacker"
        );
    }
}
