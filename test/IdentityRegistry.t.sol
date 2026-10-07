// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";

contract IdentityRegistryTest is Test {
    IdentityRegistry registry;

    bytes32 pubKeyX =
        0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

    bytes32 pubKeyY =
        0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

    bytes32 sigR =
        0x6dff0fe8309f2454e192031173bc6bce2b4bb050ee93fd096833ffd132cba8fa;

    bytes32 sigS =
        0x5363fcfd857e1b31dd6e1de820b8dd9c0cfa753260831933448db8438a04bdf0;

    function setUp() public {
        registry = new IdentityRegistry();
    }

    function testRegisterWithRealSignature() public {
        bytes32 id = registry.register(
            pubKeyX,
            pubKeyY,
            sigR,
            sigS,
            "Alice"
        );

        (
            ,
            bytes32 x,
            ,
            string memory name,
            ,
            bool active
        ) = registry.identities(id);

        assertEq(x, pubKeyX);
        assertEq(name, "Alice");
        assertTrue(active);
    }

    function testCannotRegisterTwice() public {
        registry.register(
            pubKeyX,
            pubKeyY,
            sigR,
            sigS,
            "Alice"
        );

        vm.expectRevert(
            "Identity already registered"
        );

        registry.register(
            pubKeyX,
            pubKeyY,
            sigR,
            sigS,
            "Alice again"
        );
    }

    function testRejectsInvalidSignature() public {
        bytes32 wrongR = keccak256("wrong-r");
        bytes32 wrongS = keccak256("wrong-s");

        vm.expectRevert(
            "Invalid proof of possession"
        );

        registry.register(
            pubKeyX,
            pubKeyY,
            wrongR,
            wrongS,
            "Bob"
        );
    }
}
