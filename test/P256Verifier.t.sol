// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/P256Verifier.sol";

contract P256VerifierTest is Test {
    function testVerifyRealSignature() public view {
        bytes32 pubKeyX =
            0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

        bytes32 pubKeyY =
            0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

        bytes32 messageHash =
            0x97bc91ab8a9d2caa74a6da075cbb338ed0b845738ee6c4b987eafe01a87952d4;

        bytes32 sigR =
            0xe87c3644300d358428db111ffba5e6572149cc94dba97dce94e15985793e9916;

        bytes32 sigS =
            0x81b6a7cfc3913264d2553bfbab842de8a2c7f3ed326bd8af6505f685de2c6350;

        bool result = P256Verifier.verify(
            messageHash,
            sigR,
            sigS,
            pubKeyX,
            pubKeyY
        );

        assertTrue(
            result,
            "Real P256 signature should verify successfully"
        );
    }

    function testRejectsBadSignature() public view {
        bytes32 pubKeyX =
            0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

        bytes32 pubKeyY =
            0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

        bytes32 messageHash =
            0x97bc91ab8a9d2caa74a6da075cbb338ed0b845738ee6c4b987eafe01a87952d4;

        bytes32 wrongR = keccak256("wrong-r");
        bytes32 wrongS = keccak256("wrong-s");

        bool result = P256Verifier.verify(
            messageHash,
            wrongR,
            wrongS,
            pubKeyX,
            pubKeyY
        );

        assertFalse(
            result,
            "Bad signature should not verify"
        );
    }
}
