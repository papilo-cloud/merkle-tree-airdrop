// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interface/MerkleProof.sol";

/**
 * @title MerkleWhitelist
 * @dev Example contract using Merkle proofs for whitelisting
 */
contract MerkleWhitelist is MerkleProof {
    using MerkleProof for bytes32[];

    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    mapping(address => bool) public whitelisted;

    event Claimed(address indexed account, uint256 amount);
    event Whitelisted(address indexed account);
    event MerkleRootUpdated(bytes32 newMerkleRoot);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /**
     * @dev Allows whitelisted users to claim tokens
     * @param proof Merkle proof
     * @param amount Amount to claim
     */
    function claim(
        bytes32[] calldata proof,
        uint256 amount
    ) external {
        require(
            !claimed[msg.sender],
            "Address has already claimed tokens."
        );

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(
            proof.verify(merkleRoot, leaf),
            "Invalid Proof"
        );

        claimed[msg.sender] = true;

        // Transfer logic would go here
        emit Claimed(msg.sender, amount);
    }

    /**
     * @dev Verify and add an address to the whitelist
     * @param account Address to whitelist
     * @param proof Merkle proof
     */
    function whitelistAddress(
        address account,
        bytes32[] calldata proof
    ) external {
        bytes32 leaf = keccak256(abi.encodePacked(account));
        require(
            proof.verify(merkleRoot, leaf),
            "Invalid Proof"
        );

        whitelisted[account] = true;
        emit Whitelisted(account);
    }

    
    /**
     * @dev Verify if an address is whitelisted without claiming
     * @param account Address to check
     * @param amount Amount associated with address
     * @param proof Merkle proof
     * @return bool True if whitelisted
     */
    function isWhitelisted(
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        return proof.verify(merkleRoot, leaf);
    }

    /**
     * @dev Updates the Merkle root (only owner should call this)
     * @param _merkleRoot New Merkle root
     */
    function updateMerkleRoot(bytes32 _merkleRoot) external {
        merkleRoot = _merkleRoot;
        emit MerkleRootUpdated(_merkleRoot);
    }
}