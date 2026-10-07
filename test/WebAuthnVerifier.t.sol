// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/WebAuthnVerifier.sol";

contract Base64Wrapper {
    function encode(bytes memory data) external pure returns (string memory) {
        return WebAuthnVerifier._base64UrlEncode(data);
    }
}

contract WebAuthnVerifierTest is Test {
    Base64Wrapper wrapper;

    function setUp() public {
        wrapper = new Base64Wrapper();
    }

    function testKnownVectors() public view {
        assertEq(wrapper.encode(""), "");
        assertEq(wrapper.encode("f"), "Zg");
        assertEq(wrapper.encode("fo"), "Zm8");
        assertEq(wrapper.encode("foo"), "Zm9v");
        assertEq(wrapper.encode("foob"), "Zm9vYg");
        assertEq(wrapper.encode("fooba"), "Zm9vYmE");
        assertEq(wrapper.encode("foobar"), "Zm9vYmFy");
    }

    function testEncodes32ByteHash() public view {
        bytes32 hash =
            0x97bc91ab8a9d2caa74a6da075cbb338ed0b845738ee6c4b987eafe01a87952d4;

        string memory encoded =
            wrapper.encode(abi.encodePacked(hash));

        assertEq(bytes(encoded).length, 43);
    }
}
