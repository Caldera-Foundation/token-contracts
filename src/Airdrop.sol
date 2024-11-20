// SPDX-License-Identifier: MIT
pragma solidity =0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title Airdrop Contract
/// @notice This contract implements a token airdrop based on a Merkle tree for
///         efficient proof of inclusion. There are two types of claims:
///
///           1. Address claims: for users who have an eligible Ethereum address
///           2. GitHub claims: for users who have an eligible GitHub account
///
///         To verify GitHub account ownership, we require users to authenticate
///         with a backend server (which we can provide). Once the backend server
///         verifies that the user has authenticated with GitHub successfully, it
///         signs a message containing the user's (unchecksummed) Ethereum address
///         and GitHub username.
///
///         The user can send that signed message to the `Airdrop` contract,
///         which then verifies the authenticity of the signature. If verification
///         is successful, the contract transfers the associated GitHub-based
///         allocation to the sender.
///
///         This is secure as long as the private key that signs the message
///         containing the user's Ethereum address and GitHub username is not
///         leaked outside of the backend server, and the backend's GitHub OAuth
///         client secret is not compromised.
///
///         The owner can be set to the zero address to disable upgrades and changes
///         to state variables.
contract Airdrop is Initializable, UUPSUpgradeable, PausableUpgradeable, OwnableUpgradeable {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    using MessageHashUtils for bytes;

    address public airdropVault;
    address public githubSigner;
    address public token;
    bytes32 public addressClaimMerkleRoot;
    string public addressClaimMessage;
    bytes32 public githubClaimMerkleRoot;
    uint256 public startTime;
    uint256 public endTime;
    mapping(bytes32 => bool) public addressLeafClaimed;
    mapping(bytes32 => bool) public githubLeafClaimed;
    mapping(address => bool) public blocked;

    event AirdropVaultSet(address airdropVault);
    event GithubSignerSet(address githubSigner);
    event TokenSet(address token);
    event AddressClaimMerkleRootSet(bytes32 addressClaimMerkleRoot);
    event AddressClaimMessageSet(string addressClaimMessage);
    event GithubClaimMerkleRootSet(bytes32 githubClaimMerkleRoot);
    event StartTimeSet(uint256 startTime);
    event EndTimeSet(uint256 endTime);
    event AddressBlocklistUpdated(address indexed account, bool isBlocked);
    event AddressClaimed(address indexed account, uint256 amount);
    event GithubClaimed(address indexed account, string indexed githubUsername, uint256 amount);

    error InvalidAirdropVault();
    error InvalidGithubSigner();
    error InvalidToken();
    error InvalidClaimPeriod();
    error StartTimeTooLate();
    error EndTimeTooEarly();
    error BlockedAddress();
    error InvalidAddressSignature();
    error InvalidGithubOwnershipVerificationSignature();
    error InvalidMerkleProof();
    error AlreadyClaimed();
    error ClaimPeriodNotStarted();
    error ClaimPeriodEnded();
    error TermsNotAccepted();

    /// @dev Modifier to require that the current block timestamp is within the claim period.
    modifier whenWithinClaimPeriod() {
        _requireWithinClaimPeriod();
        _;
    }

    /// @dev Modifier to require that the current sender is not blocked.
    modifier whenSenderNotBlocked() {
        _requireSenderNotBlocked();
        _;
    }

    /// @dev Modifier to require that the address signature is valid and matches the sender.
    modifier withValidAddressSignature(bytes memory addressSignature) {
        _requireValidAddressSignature(addressSignature);
        _;
    }

    /// @dev Modifier to require that the GitHub ownership verification signature is valid and matches the sender.
    modifier withValidGithubOwnershipVerificationSignature(
        string memory githubUsername,
        bytes memory githubOwnershipVerificationSignature
    ) {
        _requireValidGithubOwnershipVerificationSignature(githubUsername, githubOwnershipVerificationSignature);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with necessary parameters.
    /// @param initialOwner The initial owner of the contract.
    /// @param airdropVault_ The address of the vault holding the tokens to be airdropped. The vault must
    ///                      approve the airdrop contract as a spender in order for claims to work. A
    ///                      Gnosis Safe is recommended.
    /// @param githubSigner_ The address of the server-side signer verifying GitHub account
    ///                      ownership.
    /// @param token_ The token to be airdropped.
    /// @param addressClaimMerkleRoot_ The root of the Merkle tree used for address claim verification.
    /// @param addressClaimMessage_ The message to sign for address claim verification. This
    ///                             message should include something to the effect of "this
    ///                             user accepts the terms and conditions of the airdrop".
    /// @param githubClaimMerkleRoot_ The root of the Merkle tree used for GitHub claim verification.
    /// @param startTime_ The start time for the airdrop.
    /// @param endTime_ The end time for the airdrop.
    function initialize(
        address initialOwner,
        address airdropVault_,
        address githubSigner_,
        address token_,
        bytes32 addressClaimMerkleRoot_,
        string memory addressClaimMessage_,
        bytes32 githubClaimMerkleRoot_,
        uint256 startTime_,
        uint256 endTime_
    ) external initializer {
        __UUPSUpgradeable_init();
        __Pausable_init();
        __Ownable_init(initialOwner);

        if (airdropVault_ == address(0)) {
            revert InvalidAirdropVault();
        }

        if (githubSigner_ == address(0)) {
            revert InvalidGithubSigner();
        }

        if (token_ == address(0)) {
            revert InvalidToken();
        }

        if (startTime_ > endTime_) {
            revert InvalidClaimPeriod();
        }

        airdropVault = airdropVault_;
        githubSigner = githubSigner_;
        token = token_;
        addressClaimMerkleRoot = addressClaimMerkleRoot_;
        addressClaimMessage = addressClaimMessage_;
        githubClaimMerkleRoot = githubClaimMerkleRoot_;
        startTime = startTime_;
        endTime = endTime_;

        emit AirdropVaultSet(airdropVault_);
        emit GithubSignerSet(githubSigner_);
        emit TokenSet(token_);
        emit AddressClaimMerkleRootSet(addressClaimMerkleRoot_);
        emit AddressClaimMessageSet(addressClaimMessage_);
        emit GithubClaimMerkleRootSet(githubClaimMerkleRoot_);
        emit StartTimeSet(startTime_);
        emit EndTimeSet(endTime_);
    }

    /// @notice Pauses the contract, preventing claims.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract, allowing claims.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Sets a new airdrop vault address.
    /// @param airdropVault_ The new airdrop vault address.
    function setAirdropVault(address airdropVault_) external onlyOwner {
        airdropVault = airdropVault_;
        emit AirdropVaultSet(airdropVault_);
    }

    /// @notice Sets a new GitHub signer address.
    /// @param githubSigner_ The new GitHub signer address.
    function setGithubSigner(address githubSigner_) external onlyOwner {
        githubSigner = githubSigner_;
        emit GithubSignerSet(githubSigner_);
    }

    /// @notice Sets the start time for the airdrop.
    /// @param timestamp The start time as a timestamp.
    function setStartTime(uint256 timestamp) external onlyOwner {
        if (timestamp > endTime) {
            revert StartTimeTooLate();
        }
        startTime = timestamp;
        emit StartTimeSet(timestamp);
    }

    /// @notice Sets the end time for the airdrop.
    /// @param timestamp The end time as a timestamp.
    function setEndTime(uint256 timestamp) external onlyOwner {
        if (startTime > timestamp) {
            revert EndTimeTooEarly();
        }
        endTime = timestamp;
        emit EndTimeSet(timestamp);
    }

    /// @notice Updates the blocklist.
    /// @param accounts The array of addresses.
    /// @param status The blocklist status to set for the addresses.
    function updateBlocklist(address[] calldata accounts, bool status) external onlyOwner {
        for (uint256 i; i < accounts.length; i++) {
            blocked[accounts[i]] = status;
            emit AddressBlocklistUpdated(accounts[i], status);
        }
    }

    /// @notice Updates the Merkle root for the address claim tree.
    /// @param addressClaimMerkleRoot_ The new address claim Merkle root.
    function setAddressClaimMerkleRoot(bytes32 addressClaimMerkleRoot_) external onlyOwner {
        addressClaimMerkleRoot = addressClaimMerkleRoot_;
        emit AddressClaimMerkleRootSet(addressClaimMerkleRoot_);
    }

    /// @notice Updates the Merkle root for the GitHub claim tree.
    /// @param githubClaimMerkleRoot_ The new Github claim Merkle root.
    function setGithubClaimMerkleRoot(bytes32 githubClaimMerkleRoot_) external onlyOwner {
        githubClaimMerkleRoot = githubClaimMerkleRoot_;
        emit GithubClaimMerkleRootSet(githubClaimMerkleRoot_);
    }

    /// @notice Sets a new message for address claim verification.
    /// @param addressClaimMessage_ The new message.
    function setAddressClaimMessage(string memory addressClaimMessage_) external onlyOwner {
        addressClaimMessage = addressClaimMessage_;
        emit AddressClaimMessageSet(addressClaimMessage_);
    }

    /// @notice Allows eligible addresses to claim their airdrop with a signature
    ///         for verification.
    /// @param amount The amount of tokens to claim.
    /// @param proof The Merkle proof to prove eligibility for the claim.
    /// @param signature The signature to verify the claim.
    function addressClaim(uint256 amount, bytes32[] calldata proof, bytes memory signature)
        external
        whenNotPaused
        whenWithinClaimPeriod
        whenSenderNotBlocked
        withValidAddressSignature(signature)
    {
        _addressClaim(proof, amount);
    }

    /// @notice Allows eligible GitHub users to claim their airdrop with a signature for verification.
    /// @param githubUsername The username of the GitHub account to claim for.
    /// @param amount The amount of tokens to claim.
    /// @param proof The Merkle proof to prove eligibility for the claim.
    /// @param addressSignature The signature to verify the address.
    /// @param githubOwnershipVerificationSignature The signature to verify GitHub account ownership.
    function githubClaim(
        string calldata githubUsername,
        uint256 amount,
        bytes32[] calldata proof,
        bytes memory addressSignature,
        bytes memory githubOwnershipVerificationSignature
    )
        external
        whenNotPaused
        whenWithinClaimPeriod
        whenSenderNotBlocked
        withValidAddressSignature(addressSignature)
        withValidGithubOwnershipVerificationSignature(githubUsername, githubOwnershipVerificationSignature)
    {
        _githubClaim(proof, githubUsername, amount);
    }

    /// @notice Allows eligible users to claim their address and GitHub airdrop allocations in a single call.
    /// @param addressAmount The amount of tokens to claim as a result of address allocation.
    /// @param addressProof The Merkle proof to prove eligibility for the address claim.
    /// @param addressSignature The signature to verify the address.
    /// @param githubUsername The username of the GitHub account to claim for.
    /// @param githubAmount The amount of tokens to claim as a result of GitHub allocation.
    /// @param githubProof The Merkle proof to prove eligibility for the GitHub claim.
    /// @param githubOwnershipVerificationSignature The signature to verify GitHub account ownership.
    function combinedClaim(
        uint256 addressAmount,
        bytes32[] calldata addressProof,
        bytes memory addressSignature,
        string calldata githubUsername,
        uint256 githubAmount,
        bytes32[] calldata githubProof,
        bytes memory githubOwnershipVerificationSignature
    )
        external
        whenNotPaused
        whenWithinClaimPeriod
        whenSenderNotBlocked
        withValidAddressSignature(addressSignature)
        withValidGithubOwnershipVerificationSignature(githubUsername, githubOwnershipVerificationSignature)
    {
        _addressClaim(addressProof, addressAmount);
        _githubClaim(githubProof, githubUsername, githubAmount);
    }

    /// @notice Returns the GitHub claim verification message for the given address and username.
    /// @param address_ The Ethereum address that claims to own the GitHub account.
    /// @param githubUsername The username of the GitHub account the address is asserting ownership of.
    /// @return The GitHub claim verification message.
    function getGithubClaimVerificationMessage(address address_, string memory githubUsername)
        public
        pure
        returns (string memory)
    {
        return string.concat(
            "This attests that the following association between (sender_address,github_username) has been verified: ",
            "(",
            Strings.toHexString(address_),
            ",",
            githubUsername,
            ")"
        );
    }

    /// @dev Internal function to handle upgrades, only callable by the owner.
    /// @param newImplementation The address of the new implementation.
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @dev Internal function to handle address claims.
    /// @param proof The Merkle proof to prove eligibility for the claim.
    /// @param amount The amount of tokens to claim.
    function _addressClaim(bytes32[] calldata proof, uint256 amount) internal {
        address sender = msg.sender;
        // Double hash so we can use OpenZeppelin's merkle-tree library
        // https://github.com/OpenZeppelin/merkle-tree?tab=readme-ov-file#validating-a-proof-in-solidity
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(sender, amount))));
        if (addressLeafClaimed[leaf]) {
            revert AlreadyClaimed();
        }

        if (!MerkleProof.verifyCalldata(proof, addressClaimMerkleRoot, leaf)) {
            revert InvalidMerkleProof();
        }

        addressLeafClaimed[leaf] = true;
        emit AddressClaimed(sender, amount);
        IERC20(token).safeTransferFrom(airdropVault, sender, amount);
    }

    /// @dev Internal function to handle GitHub claims.
    /// @param proof The Merkle proof to prove eligibility for the claim.
    /// @param amount The amount of tokens to claim.
    function _githubClaim(bytes32[] calldata proof, string calldata githubUsername, uint256 amount) internal {
        address sender = msg.sender;
        // Double hash so we can use OpenZeppelin's merkle-tree library
        // https://github.com/OpenZeppelin/merkle-tree?tab=readme-ov-file#validating-a-proof-in-solidity
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(githubUsername, amount))));
        if (githubLeafClaimed[leaf]) {
            revert AlreadyClaimed();
        }

        if (!MerkleProof.verifyCalldata(proof, githubClaimMerkleRoot, leaf)) {
            revert InvalidMerkleProof();
        }

        githubLeafClaimed[leaf] = true;
        emit GithubClaimed(sender, githubUsername, amount);
        IERC20(token).safeTransferFrom(airdropVault, sender, amount);
    }

    /// @notice Requires that the current block timestamp is within the claim period.
    function _requireWithinClaimPeriod() internal view {
        if (block.timestamp < startTime) {
            revert ClaimPeriodNotStarted();
        }
        if (block.timestamp > endTime) {
            revert ClaimPeriodEnded();
        }
    }

    /// @notice Requires that the current sender is not blocked.
    function _requireSenderNotBlocked() internal view {
        if (blocked[msg.sender]) {
            revert BlockedAddress();
        }
    }

    /// @notice Requires that the address signature is valid and matches the sender.
    /// @param addressSignature The signature to verify.
    function _requireValidAddressSignature(bytes memory addressSignature) internal view {
        if (bytes(addressClaimMessage).toEthSignedMessageHash().recover(addressSignature) != msg.sender) {
            revert InvalidAddressSignature();
        }
    }

    /// @notice Requires that the GitHub ownership verification signature is valid and matches the sender.
    /// @param githubUsername The username of the GitHub account to claim for.
    /// @param githubOwnershipVerificationSignature The signature to verify.
    function _requireValidGithubOwnershipVerificationSignature(
        string memory githubUsername,
        bytes memory githubOwnershipVerificationSignature
    ) internal view {
        // When a user successfully authenticates with GitHub on the claim/distribution page, the backend
        // will return a signature containing the user's claimed address and GitHub username. In this block
        // of code, we verify that the signature passed by the caller actually corresponds to this message
        // and was signed by the (trusted) signer on the backend.
        string memory githubOwnershipVerificationMessage = getGithubClaimVerificationMessage(msg.sender, githubUsername);

        if (
            bytes(githubOwnershipVerificationMessage).toEthSignedMessageHash().recover(
                githubOwnershipVerificationSignature
            ) != githubSigner
        ) {
            revert InvalidGithubOwnershipVerificationSignature();
        }
    }
}
