// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {AuthConfigManager} from "../src/AuthConfigManager.sol";
import {AnchorViews} from "../src/AnchorViews.sol";

contract DeployAnchor is Script {
    function run()
        external
        returns (
            IdentityRegistry identityRegistry,
            AuthConfigManager authConfigManager,
            AnchorViews anchorViews
        )
    {
        vm.startBroadcast();

        identityRegistry = new IdentityRegistry();
        authConfigManager = new AuthConfigManager(address(identityRegistry));
        anchorViews = new AnchorViews(
            address(identityRegistry),
            address(authConfigManager)
        );

        vm.stopBroadcast();
    }
}
