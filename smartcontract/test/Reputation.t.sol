// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import {Reputation} from "src/Reputation.sol";
import {ReputationFactory} from "src/factory.sol";

contract ReputationTest is Test {
    Reputation rep;
    address owner = address(this);
    string constant USER = "alice";

    function setUp() public {
        // Deploy a fresh contract owned by this test contract
        rep = new Reputation(owner, address(0));
    }

    function testAddUserAndGetUserData() public {
        bytes32 pwd = keccak256(abi.encodePacked("pw"));
        rep.addUser(USER, "salt", pwd, 10, 20);
        Reputation.UserData memory u = rep.getUserData(USER);
        assertEq(u.username, USER);
        assertEq(u.salt, "salt");
        assertEq(u.passwordHash, pwd);
        assertEq(u.downloadSize, 10);
        assertEq(u.uploadSize, 20);
    }

    function testOnlyOwnerGuard_addUser() public {
        Reputation other = new Reputation(address(0xBEEF), address(0));
        vm.prank(address(0xCAFE));
        vm.expectRevert(bytes("Only the owner can call this function."));
        other.addUser("bob", "s", bytes32(uint256(1)), 0, 0);
    }

    function testUpdateUser() public {
        rep.addUser(USER, "s", bytes32(uint256(1)), 1, 2);
        rep.updateUser(USER, 100, 200);
        Reputation.UserData memory u = rep.getUserData(USER);
        assertEq(u.downloadSize, 100);
        assertEq(u.uploadSize, 200);
    }

    function testMigrateUserDataFromReferrer() public {
        // Old contract holds data
        Reputation oldRep = new Reputation(owner, address(0));
        bytes32 pwd = keccak256(bytes("old"));
        oldRep.addUser(USER, "oldsalt", pwd, 7, 9);

        // New contract points to old as referrer
        Reputation newRep = new Reputation(owner, address(oldRep));
        // Initially empty
        assertEq(newRep.getUserData(USER).passwordHash, bytes32(0));

        // Migrate pulls from referrer
        newRep.migrateUserData(USER);
        Reputation.UserData memory u = newRep.getUserData(USER);
        assertEq(u.passwordHash, pwd);
        assertEq(u.downloadSize, 7);
        assertEq(u.uploadSize, 9);
    }

    function testSetAndGetOffchainDataUrl() public {
        new string[](0);
        string memory url = "ipfs://bafy...";
        rep.setOffchainDataUrl(url);
        assertEq(rep.getOffchainDataUrl(), url);
    }
}

contract FactoryTest is Test {
    function testCreateReputationSetsOwnerAndReferrer() public {
        ReputationFactory f = new ReputationFactory();
        Reputation ref = new Reputation(address(this), address(0));
        address created = f.createReputation(address(ref), hex"");
        Reputation rep = Reputation(created);
        assertEq(rep.owner(), address(this));
        assertEq(rep.referrerReputation(), address(ref));
    }
}


