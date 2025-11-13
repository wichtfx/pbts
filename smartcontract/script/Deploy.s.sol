// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script, console} from "forge-std/Script.sol";
import {ReputationFactory} from "../src/factory.sol";

contract Deploy is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        ReputationFactory factory = new ReputationFactory();
        console.log("ReputationFactory deployed at:", address(factory));
        vm.stopBroadcast();
    }
}
