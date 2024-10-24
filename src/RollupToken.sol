// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {ERC20PermitUpgradeable} from
    "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {ERC20VotesUpgradeable} from
    "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20VotesUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {NoncesUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/NoncesUpgradeable.sol";

/// @title Rollup token contract
/// @notice Based on ENS: https://etherscan.io/token/0xc18360217d8f7ab5e7c516566761ea12ce7f9d72
///         The owner can be set to the zero address to disable upgrades, changes to state
///         variables, and minting.
contract RollupToken is
    Initializable,
    UUPSUpgradeable,
    ERC20Upgradeable,
    ERC20PermitUpgradeable,
    ERC20VotesUpgradeable,
    OwnableUpgradeable
{
    // Maximum supply; better to be a constant than configurable
    uint256 public constant MAX_SUPPLY = 10_000_000_000 ether;
    // 5% initial maximum inflation rate
    uint256 public constant INITIAL_MINT_CAP_BIPS = 500;
    uint256 public constant MINIMUM_MINT_INTERVAL = 365 days;
    uint256 public mintCapBips;
    uint256 public nextMint; // Timestamp

    event MintCapLowered(uint256 previousMintCapBips, uint256 newMintCapBips);

    error SupplyCapExceeded();
    error MintCapExceeded();
    error MintPeriodNotStarted();
    error MintCapTooHigh();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Constructs the token contract.
    /// @dev Initializes the ERC20, ERC20Permit, and Ownable contracts, mints initial supply
    ///      to the airdrop vault, and sets the next minting time.
    /// @param tokenName The name of the token.
    /// @param tokenSymbol The symbol of the token.
    /// @param initialOwner The initial owner of the contract.
    /// @param airdropVault The address of the vault holding the tokens to be airdropped. The vault must
    ///                      approve the airdrop contract as a spender in order for claims to work. A
    ///                      Gnosis Safe is recommended.
    /// @param airdropSupply The amount of tokens to mint initially for the airdrop.
    function initialize(
        string memory tokenName,
        string memory tokenSymbol,
        address initialOwner,
        address airdropVault,
        uint256 airdropSupply
    ) external initializer {
        __UUPSUpgradeable_init();
        __ERC20_init(tokenName, tokenSymbol);
        __ERC20Permit_init(tokenName);
        __ERC20Votes_init();
        __Ownable_init(initialOwner);

        if (airdropSupply > MAX_SUPPLY) {
            revert SupplyCapExceeded();
        }

        mintCapBips = INITIAL_MINT_CAP_BIPS;
        nextMint = block.timestamp + MINIMUM_MINT_INTERVAL;
        _mint(airdropVault, airdropSupply);
    }

    /// @notice Mints new tokens. Can only be executed once every `minimumMintInterval`, by the owner,
    ///         and cannot exceed `mintCapBips / 10000` fraction of the current total supply.
    /// @param to The address to mint the new tokens to.
    /// @param amount The quantity of tokens to mint.
    function mint(address to, uint256 amount) external onlyOwner {
        if (amount > (totalSupply() * mintCapBips) / 10000) {
            revert MintCapExceeded();
        }

        if (block.timestamp < nextMint) {
            revert MintPeriodNotStarted();
        }

        if (totalSupply() + amount > MAX_SUPPLY) {
            revert SupplyCapExceeded();
        }

        nextMint = block.timestamp + MINIMUM_MINT_INTERVAL;
        _mint(to, amount);
    }

    /// @notice Lowers the mint cap to the given percentage of the current total supply
    ///         (in basis points). Note that once the mint cap is lowered, it cannot be
    ///         raised again.
    /// @param newMintCapBips The new mint cap in basis points (10000 = 100%).
    function lowerMintCap(uint256 newMintCapBips) external onlyOwner {
        if (newMintCapBips > mintCapBips) {
            revert MintCapTooHigh();
        }
        mintCapBips = newMintCapBips;
        emit MintCapLowered(mintCapBips, newMintCapBips);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _update(address from, address to, uint256 value)
        internal
        virtual
        override(ERC20Upgradeable, ERC20VotesUpgradeable)
    {
        super._update(from, to, value);
    }

    function nonces(address owner)
        public
        view
        virtual
        override(NoncesUpgradeable, ERC20PermitUpgradeable)
        returns (uint256)
    {
        return super.nonces(owner);
    }
}
