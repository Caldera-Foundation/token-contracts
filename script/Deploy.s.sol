// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script, console} from "forge-std/Script.sol";
import {Airdrop} from "../src/Airdrop.sol";
import {RollupToken} from "../src/RollupToken.sol";

contract DeployScript is Script {
    Airdrop public airdrop;
    RollupToken public token;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address initialOwner = msg.sender;
        address airdropVault = msg.sender;

        RollupToken unproxiedRollupToken = new RollupToken();
        ERC1967Proxy proxy = new ERC1967Proxy(address(unproxiedRollupToken), "");
        token = RollupToken(address(proxy));
        token.initialize("Test Token", "TEST", initialOwner, airdropVault, 1000 ether);

        Airdrop unproxiedAirdrop = new Airdrop();
        ERC1967Proxy airdropProxy = new ERC1967Proxy(address(unproxiedAirdrop), "");
        airdrop = Airdrop(address(airdropProxy));
        (address githubSigner, uint256 githubSignerPk) = makeAddrAndKey("github_signer");

        bytes32 addressClaimMerkleRoot = bytes32(0x98a2c3e99568b69acd241df2a88423961522cbcfe52c487414366ffa659cebe9);
        string memory addressClaimMessage = "I accept the terms and conditions.";
        bytes32 githubClaimMerkleRoot = bytes32(0x68cb01563116d6ddc2d252c4bdf203043d6a574bb4e160c610d08b876d7d2d1b);

        airdrop.initialize(
            initialOwner,
            airdropVault,
            githubSigner,
            address(token),
            addressClaimMerkleRoot,
            addressClaimMessage,
            githubClaimMerkleRoot,
            block.timestamp,
            block.timestamp + 365 days
        );

        // Approve airdrop contract to spend tokens from sender
        token.approve(address(airdrop), type(uint256).max);
        vm.stopBroadcast();

        console.log("address(airdrop)", address(airdrop));
        console.log("githubSignerPk");
        console.logBytes32(bytes32(githubSignerPk));
    }
}
