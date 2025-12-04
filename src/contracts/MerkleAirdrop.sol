// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interface/MerkleProof.sol";

/**
 * @title MerkleAirdrop
 * @dev Advanced example with indexed proofs for gas optimization
 */
contract MerkleAirdrop is MerkleProof {
    using MerkleProof for bytes32[];

    bytes32 public merkleRoot;
    mapping(uint256 => uint256) private claimedBitMap;

    event Claimed(uint256 index, address indexed claimant, uint256 amount);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /**
     * @dev Check if an index has been claimed
     * @param index Position in the Merkle tree
     * @return bool True if claimed
     */
    function isClaimed(uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return (claimedWord & mask) == mask;
    }

    /**
     * @dev Mark an index as claimed
     * @param index Position in the Merkle tree
     */
    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] =
            claimedBitMap[claimedWordIndex] |
            (1 << claimedBitIndex);
    }

    /**
     * @dev Claim airdrop with index-based verification
     * @param index Position in Merkle tree
     * @param account Address to receive tokens
     * @param amount Amount to claim
     * @param proof Merkle proof
     */
    function claim(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        require(!isClaimed(index), "Airdrop already claimed.");
        require(msg.sender == account, "Can only claim for yourself");

        // Create leaf hash
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));

        require(
            verify(index, account, amount, proof),
            "Invalid Merkle Proof."
        );

        // Mark as claimed
        _setClaimed(index);

        emit Claimed(index, account, amount);
    }

    /**
     * @dev Verify eligibility without claiming
     * @param index Position in tree
     * @param account Address to check
     * @param amount Amount to check
     * @param proof Merkle proof
     * @return bool True if valid
     */
    function verify(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        return proof.verifyWithIndex(merkleRoot, leaf, index);
    }