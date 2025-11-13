// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

// Import the Reputation contract so the factory knows how to create it.
import "./Reputation.sol";

/**
 * @title ReputationFactory
 * @dev This is the contract your TEE will call. Its sole purpose is to create
 * a new Reputation contract, linking it to a previous one for data lookups.
 */

contract ReputationFactory {

    // Event to be emitted when a new Reputation is created for easier off-chain tracking.
    event ReputationCreated(address newReputationAddress, address owner, address referrer, bytes attestation);

    /**
     * @dev Creates a new Reputation contract and assigns ownership to the caller (the TEE).
     * @param _referrerReputation The address of an existing Reputation to chain lookups to.
     * Pass address(0) to create a Reputation with no history.
     * @return address The address of the newly created Reputation contract.
     */
    function createReputation(address _referrerReputation, bytes calldata _attestation) public returns (address) {
        // Create a new Reputation instance, passing the creator (msg.sender)
        // and the referrer's address to the Reputation's constructor.
        Reputation newReputation = new Reputation(msg.sender, _referrerReputation);

        // Emit an event to log the creation on-chain.
        emit ReputationCreated(address(newReputation), msg.sender, _referrerReputation, _attestation);

        // Return the address of the contract we just created.
        return address(newReputation);
    }
}
