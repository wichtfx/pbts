// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Test, console} from "forge-std/Test.sol";
import {Reputation} from "../src/Reputation.sol";

contract FactoryTest is Test {
    Reputation public reputation;
    address public owner; // Represents the first TEE
    address public tee2;  // Represents the second TEE after a "failover"

    function setUp() public {
        // Deploy a new reputation contract before each test
        reputation = new Reputation(address(this), address(0));
        owner = address(this); // Use the test contract as the owner
        tee2 = address(0x2);   // A mock address for the second TEE
    }

    function test_CreateFirstReputation() public {
        // Create the first reputation with no referrer
        Reputation firstReputation = new Reputation(owner, address(0));
        assertTrue(address(firstReputation) != address(0));

        // Verify the owner is the TEE that created the contract
        assertEq(firstReputation.owner(), owner);
        // Verify it has no referrer
        assertEq(firstReputation.referrerReputation(), address(0));
    }

    function test_CreateChainedReputation() public {
        // 1. Create the first reputation
        Reputation firstReputation = new Reputation(owner, address(0));

        // 2. Add some data to the first reputation as the owner
        firstReputation.addUser(
            "alice", "salt123", keccak256("pass123"), 100, 50
        );

        // 3. TEE 2 takes over and creates a new reputation, referring to the first one
        // We use vm.prank to simulate the call coming from tee2's address
        vm.prank(tee2);
        Reputation secondReputation = new Reputation(tee2, address(firstReputation));

        // 4. Verify the new reputation is owned by tee2 and refers to the first one
        assertEq(secondReputation.owner(), tee2);
        assertEq(secondReputation.referrerReputation(), address(firstReputation));

        // 5. CRITICAL TEST: Look up "alice" through the new reputation
        // It should find the data by chaining the lookup to the first reputation.
        secondReputation.migrateUserData("alice");
        Reputation.UserData memory aliceData = secondReputation.getUserData("alice");
        assertEq(aliceData.username, "alice");
        assertEq(aliceData.downloadSize, 100);
        assertEq(aliceData.uploadSize, 50);
    }

    function test_UpdateDataInNewReputation() public {
        // Setup a chain of two reputations, with "alice" in the first one
        Reputation firstReputation = new Reputation(owner, address(0));
        firstReputation.addUser(
            "alice", "salt123", keccak256("pass123"), 100, 50
        );
        vm.prank(tee2);
        Reputation secondReputation = new Reputation(tee2, address(firstReputation));
        secondReputation.migrateUserData("alice");

        // Now, as tee2, update Alice's data. This writes it to the *new* reputation
        vm.prank(tee2);
        secondReputation.updateUser(
            "alice", 200, 150
        );

        // Look up the data again through the second reputation
        Reputation.UserData memory aliceData = secondReputation.getUserData("alice");
        
        // It should return the NEW data, because it finds it in the second contract first
        assertEq(aliceData.downloadSize, 200);
        assertEq(aliceData.uploadSize, 150);
        assertEq(aliceData.salt, "salt123"); // Salt should remain unchanged as it's not updated
    }

    function test_OnlyOwnerCanUpdateOffchainDataUrl() public {
        // Setup a chain of two reputations, with "alice" in the first one
        Reputation firstReputation = new Reputation(owner, address(0));
        firstReputation.addUser(
            "alice", "salt123", keccak256("pass123"), 100, 50
        );

        // Try to update the offchain data url as a non-owner
        vm.prank(address(0x3));
        vm.expectRevert(bytes("Only the owner can call this function."));
        firstReputation.setOffchainDataUrl("https://ipfs.io/ipfs/Qm1234567890");
    }
}

