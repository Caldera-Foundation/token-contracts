// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test} from "forge-std/Test.sol";
import {RollupToken} from "../src/RollupToken.sol";

contract RollupTokenTest is Test {
    RollupToken public token;

    function setUp() public {
        RollupToken unproxiedRollupToken = new RollupToken{salt: "hello"}();
        ERC1967Proxy proxy = new ERC1967Proxy(address(unproxiedRollupToken), "");
        token = RollupToken(address(proxy));
        token.initialize("Test Token", "TEST", address(this), address(this), 1 ether);
    }

    function testInitialSupply() public view {
        assertEq(token.totalSupply(), 1 ether, "Initial supply should be 1");
    }

    function testInitializeWithExcessiveSupply() public {
        RollupToken unproxiedNewToken = new RollupToken();
        ERC1967Proxy proxy = new ERC1967Proxy(address(unproxiedNewToken), "");
        RollupToken newToken = RollupToken(address(proxy));
        vm.expectRevert(RollupToken.SupplyCapExceeded.selector);
        newToken.initialize("Test", "TST", address(this), address(this), 10_000_000_001 ether);
    }

    function testInitialOwner() public view {
        assertEq(token.owner(), address(this), "Initial owner should be the Tests contract");
    }

    function testName() public view {
        assertEq(token.name(), "Test Token", "Token name should be Test Token");
    }

    function testSymbol() public view {
        assertEq(token.symbol(), "TEST", "Token symbol should be TEST");
    }

    function testMintInterval() public view {
        assertEq(token.MINIMUM_MINT_INTERVAL(), 365 days, "Minimum mint interval should be 365 days");
    }

    function testMintCap() public view {
        assertEq(token.mintCapBips(), 500, "Mint cap should be 500 bips (5%)");
    }

    function testMaxSupply() public view {
        assertEq(token.MAX_SUPPLY(), 10_000_000_000 ether, "Max supply should be 10 billion");
    }

    function testMaxSupplyCap() public {
        // This gets us right below 10 billion
        for (uint256 i = 0; i < 471; i++) {
            vm.warp(block.timestamp + 365 days);
            uint256 currentSupply = token.totalSupply();
            uint256 amountToMint = (currentSupply * token.mintCapBips()) / 10000;
            token.mint(address(this), amountToMint);
        }

        vm.warp(block.timestamp + 365 days);
        assert(token.totalSupply() < token.MAX_SUPPLY());
        token.mint(address(this), token.MAX_SUPPLY() - token.totalSupply());

        vm.warp(block.timestamp + 365 days);
        assertEq(token.totalSupply(), token.MAX_SUPPLY());

        vm.expectRevert(RollupToken.SupplyCapExceeded.selector);
        token.mint(address(this), 1);
    }

    function testMint() public {
        uint256 initialSupply = token.totalSupply();
        vm.warp(block.timestamp + 365 days);
        token.mint(address(this), 0.05 ether);
        assertEq(token.totalSupply(), initialSupply + 0.05 ether, "Total supply should increase after minting");
    }

    function testMintFailBeforeInterval() public {
        vm.expectRevert(RollupToken.MintPeriodNotStarted.selector);
        token.mint(address(this), 50000000000000000);
    }

    function testMintFailExceedsCap() public {
        vm.warp(block.timestamp + 365 days);
        vm.expectRevert(RollupToken.MintCapExceeded.selector);
        token.mint(address(this), 0.051 ether);
    }

    function testMintFailNonOwner() public {
        vm.warp(block.timestamp + 365 days);
        vm.prank(address(0x1));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x1)));
        token.mint(address(this), 0.05 ether);
    }

    function testLowerMintCap() public {
        vm.warp(block.timestamp + 365 days);
        token.mint(address(this), 0.05 ether);
        token.lowerMintCap(250);
        vm.expectRevert(RollupToken.MintCapExceeded.selector);
        token.mint(address(this), 0.05 ether);
    }

    function testLowerMintCapTooHigh() public {
        vm.warp(block.timestamp + 365 days);
        token.mint(address(this), 0.05 ether);
        vm.expectRevert(RollupToken.MintCapTooHigh.selector);
        token.lowerMintCap(501); // Attempt to increase the mint cap
    }

    function testNonces() public view {
        assertEq(token.nonces(address(this)), 0);
    }
}
