# Merkle Tree Airdrop & Whitelist System

A gas-optimized implementation of Merkle trees for token airdrops, NFT whitelists, and on-chain verification systems.

## What Are Merkle Trees?

Merkle trees allow you to cryptographically prove that a piece of data belongs to a large dataset without revealing the entire dataset. Perfect for:

- **Token Airdrops**: Distribute tokens to thousands of addresses efficiently
- **NFT Whitelists**: Allow only specific addresses to mint
- **Governance**: Verify voting rights based on snapshots
- **Access Control**: Prove membership in exclusive groups

### How It Works

```
         Root Hash (stored on-chain)
              /       \
            /           \
          H(AB)        H(CD)
          /   \        /   \
        H(A) H(B)   H(C)  H(D)
         |    |      |     |
        User1 User2 User3 User4
```

**Proof Size**: Log₂(n) hashes
- 1,000 users -> ~10 hashes
- 1,000,000 users -> ~20 hashes
- 1,000,000,000 users -> ~30 hashes

## Installation

### Prerequisites

- Node.js >= 20.0.0
- npm or yarn
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/papilo-cloud/merkle-tree-airdrop.git
cd merkle-tree-airdrop

# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Edit .env with your values
# PRIVATE_KEY=your_private_key
# INFURA_API_KEY=your_infura_key
# ETHERSCAN_API_KEY=your_etherscan_key
```