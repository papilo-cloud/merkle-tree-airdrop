// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interface/MerkleProof.sol";

/**
 * @title SecureMerkleTree
 * @dev Example showing secure leaf hashing to prevent vulnerabilities
 */
contract SecureMerkleTree {
    using SecureMerkleTree for bytes32[];

    bytes32 public immutable merkleRoot;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /**
     * @dev Verify membership using properly hashed leaf
     * @param data Original data
     * @param proof Merkle proof
     * @return bool True if valid
     */
    function verifyData(
        bytes memory data,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 leaf = MerkleProof.hashLeaf(data);
        return proof.verify(merkleRoot, leaf);
    }

    /**
     * @dev Example: Verify user eligibility with complex data structure
     * @param user User address
     * @param tier Tier level
     * @param amount Allocation amount
     * @param proof Merkle proof
     * @return bool True if valid
     */
    function verifyUserAllocation(
        address user,
        uint8 tier,
        uint256 amount,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes memory data = abi.encode(user, tier, amount);
        bytes32 leaf = MerkleProof.hashLeaf(data);
        return proof.verify(merkleRoot, leaf);
    }
}