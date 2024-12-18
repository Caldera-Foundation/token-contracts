## Rollup Token Contracts

Caldera Foundation token contracts.

See `Zellic_audit_report.pdf` for audit report.

### `RollupToken.sol`

Upgradeable ERC20 token with voting and delegation (via `ERC20Votes`) and gasless approvals (via `ERC20Permit`). Also allows a configurable amount of inflation annually, up to owner's discretion. Based on [$ENS](https://etherscan.io/token/0xc18360217d8f7ab5e7c516566761ea12ce7f9d72).

Before deployment, the constants `MAX_SUPPLY` and `INITIAL_MINT_CAP_BIPS` should be reviewed and updated if necessary.

### `Airdrop.sol`

Airdrop contract for distributing tokens. Uses Merkle trees for efficient proof of inclusion (one tree for addresses, one for Github handles). Based on the [AltLayer airdrop contract](https://etherscan.io/address/0x8e2dd9bfe5214fb52882b360b8198a68ebd208ff).

To verify GitHub account ownership, we require users to authenticate with GitHub via OAuth through a separate backend server (which we can provide to customers). The backend server holds a secret private key. Once the backend server verifies that the user has authenticated with GitHub successfully, it signs a message (using the secret private key) containing the user's (unchecksummed) Ethereum address and lowercased GitHub username.

> Note: to generate the GitHub account ownership verification messages in `getGithubClaimVerificationMessage` in `Airdrop.sol`, we use Solidity's `Strings.toHexString` function to convert an `address` to an (unchecksummed) hex string. On the other hand, leaves in the actual address Merkle tree use the raw bytes of the `address` (specifically, OpenZeppelin's implementation takes an address string and ABI encodes it). Note also that leaves in the GitHub Merkle tree use lowercased usernames.

The user can send the signed message they get from the backend server to the `Airdrop` contract, which then verifies the authenticity of the signature (by checking that the recovered address matches the address corresponding to the backend's secret private key). If verification is successful, the contract transfers the associated GitHub-based allocation to the sender.

This setup is secure as long as the private key that can sign the message containing the user's Ethereum address and GitHub username is not leaked outside of the backend server, and our GitHub OAuth client secret is not leaked.

## Usage

### Install dependencies

```shell
$ pnpm install
$ forge install
```

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Deploy

```shell
$ forge script script/Deploy.s.sol:DeployScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```
