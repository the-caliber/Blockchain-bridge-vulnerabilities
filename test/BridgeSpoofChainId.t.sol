// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/BridgeSpoofChainId.sol";
import "../src/IBridge.sol";
import "../src/SignalProcessor.sol";

contract BridgeSpoofChainIdTest is Test {
    BridgeSpoofChainId bridge;
    BridgeSpoofChainId destBridge;
    SignalProcessor signalProcessor;
    address owner = address(0x1);
    address user = address(0x2);
    address token = address(0x3);
    uint256 staticFee = 0.0001 ether;

    bytes32 DOMAIN_SEPARATOR;

    function setUp() public {
        vm.startPrank(owner);
        signalProcessor = new SignalProcessor();
        bridge = new BridgeSpoofChainId(owner, address(signalProcessor));
        destBridge = new BridgeSpoofChainId(owner, address(signalProcessor));
        vm.stopPrank();
        
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("BridgeSpoofChainId")),
                keccak256(bytes("1")),
                block.chainid,
                address(bridge)
            )
        );
    }

    function test_chain_id_validation() public {
       (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(owner);
        bridge.mint(alice,1 ether);
        destBridge.mint(alice,1 ether);
        vm.stopPrank();

        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 1 ether),
            repayAddr: address(0)
        });

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridge.getDomainSeparator(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);

        // Concatenate v, r, and s into a single signature
        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridge.sendMsgPermit{value: staticFee}(transaction, signature);

        // Verify the transaction was processed
        bytes32 txHash = keccak256(abi.encode(transaction));
        vm.expectRevert("Bridge: source chain not allowed");
        destBridge.executeMessage(transaction);
    }

    function test_chain_id_spoofing() public {
        // Only src chain id 56 is allowed
        vm.prank(owner);
        destBridge.setAllowedSrcChain(56, true);
        
       (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(owner);
        bridge.mint(alice,1 ether);
        destBridge.mint(alice,1 ether);
        vm.stopPrank();

        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: 56, // Spoofed chain ID
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 1 ether),
            repayAddr: address(0)
        });

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridge.getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridge.sendMsgPermit{value: staticFee}(transaction, signature);

        // Verify the transaction was processed
        bytes32 txHash = keccak256(abi.encode(transaction));
        destBridge.executeMessage(transaction);

        assert(destBridge.msgStatus(txHash) == BridgeSpoofChainId.MsgStatus.Processed);
        assertEq(1 ether, destBridge.balanceOf(user), "receiver's balance should be increased");
        assertEq(0, destBridge.balanceOf(alice), "sender's balance should be decreased");
    }

}