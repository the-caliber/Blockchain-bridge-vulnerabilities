// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/BridgeSafeTokenSend.sol";
import "../src/IBridge.sol";
import "../src/SignalProcessor.sol";

contract BridgeSendTokenSafeTest is Test {
    BridgeSendTokenSafe bridgeSafe;
    BridgeSendTokenSafe bridgeSafeDest;
    SignalProcessor signalProcessor;
    address owner = address(0x1);
    address user = address(0x2);
    uint256 staticFee = 0.0001 ether;

    function setUp() public {
        vm.startPrank(owner);
        signalProcessor = new SignalProcessor();
        bridgeSafe = new BridgeSendTokenSafe(owner, address(signalProcessor));
        bridgeSafeDest = new BridgeSendTokenSafe(owner, address(signalProcessor));
        vm.stopPrank();
    }

    function test_sendMsg() public {
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: user,
            to: user,
            value: 1 ether,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: bytes("0"),
            repayAddr: address(0)
        });

        vm.deal(user, 2 ether);
        vm.prank(user);
        bridgeSafe.sendMsg{value: 1 ether + staticFee}(transaction);

        vm.chainId(2);

        // Mimic user's stored ETH on the bridge contract
        vm.deal(address(bridgeSafeDest), 1 ether);

        bridgeSafeDest.executeMessage(transaction);

        assertEq(address(bridgeSafeDest).balance, 0, "Bridge should have 0 ETH left");
        assertEq(address(bridgeSafe).balance, 1 ether + staticFee, "Bridge should have 1 ETH + staticFee left");
        assertEq(
            address(user).balance, 1 ether + (1 ether - staticFee), "User should have received 1 ETH on dest chain"
        );
    }

    function test_sendMsg_transfer() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.prank(owner);
        bridgeSafeDest.mint(alice, 1 ether);
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 1 ether),
            repayAddr: address(0)
        });

        vm.deal(alice, 2 ether);
        vm.prank(alice);
        bridgeSafe.sendMsg{value: staticFee}(transaction);

        vm.chainId(2);

        bridgeSafeDest.executeMessage(transaction);

        assertEq(address(bridgeSafeDest).balance, 0, "Bridge should have 0 ETH left");
        assertEq(address(bridgeSafe).balance, staticFee, "Bridge should have staticFee left");
        assertEq(bridgeSafeDest.balanceOf(user), 1 ether, "the user should have 1 token on dest chain");
        assertEq(bridgeSafeDest.balanceOf(alice), 0, "the alice should have 0 tokens on dest chain");
    }

    function test_sendMsgPermit() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: alice,
            to: user,
            value: 1 ether,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: "",
            repayAddr: address(0)
        });

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"
                ),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        // console.log("offchain structHash: "); console.logBytes32(structHash);

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridgeSafe.getDomainSeparator(), structHash));
        // console.log("offchain messageHash: "); console.logBytes32(messageHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridgeSafe.sendMsgPermit{value: 1 ether + staticFee}(transaction, signature);

        // Mimic the accumulated/received value.
        vm.deal(address(bridgeSafeDest), 1 ether);

        vm.chainId(2);

        // Verify the transaction was processed
        bytes32 txHash = keccak256(abi.encode(transaction));
        bridgeSafeDest.executeMessage(transaction);

        assert(bridgeSafeDest.msgStatus(txHash) == BridgeSendTokenSafe.MsgStatus.Processed);
        assertEq(address(bridgeSafeDest).balance, 0, "Bridge should have 0 ETH left");
        assertEq(address(bridgeSafe).balance, 1 ether + staticFee, "Bridge should have 1 ETH + staticFee left");
        assertEq(
            address(user).balance, 1 ether + (1 ether - staticFee), "User should have received 1 ETH on dest chain"
        );
    }

    function test_sendMsgPermit_transfer() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(owner);
        bridgeSafe.mint(alice, 1 ether);
        bridgeSafeDest.mint(alice, 1 ether);
        vm.stopPrank();

        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: alice,
            to: address(bridgeSafeDest), // using bridgeSafeDest instead of bridgeSafe, assuming that the both will be same on different chains.
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 1 ether),
            repayAddr: address(0)
        });

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"
                ),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridgeSafe.getDomainSeparator(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridgeSafe.sendMsgPermit{value: staticFee}(transaction, signature);

        vm.chainId(2);

        // Verify the transaction was processed
        bytes32 txHash = keccak256(abi.encode(transaction));
        bridgeSafeDest.executeMessage(transaction);

        assert(bridgeSafeDest.msgStatus(txHash) == BridgeSendTokenSafe.MsgStatus.Processed);
        assertEq(address(bridgeSafeDest).balance, 0, "Bridge should have 0 ETH left");
        assertEq(address(bridgeSafe).balance, staticFee, "Bridge should have staticFee left");
        assertEq(bridgeSafeDest.balanceOf(user), 1 ether, "the user should have 1 token on dest chain");
        assertEq(bridgeSafeDest.balanceOf(alice), 0, "the alice should have 0 tokens on dest chain");
    }

    function test_sendMsgPermit_mint() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(owner);
        bridgeSafe.mint(alice, 1 ether);
        vm.stopPrank();

        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: alice,
            to: address(0),
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("mint(address,uint256)", user, 1 ether),
            repayAddr: address(0)
        });

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"
                ),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridgeSafe.getDomainSeparator(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridgeSafe.sendMsgPermit{value: staticFee}(transaction, signature);

        vm.chainId(2);

        // Verify the transaction was processed
        bytes32 txHash = keccak256(abi.encode(transaction));
        bridgeSafeDest.executeMessage(transaction);

        assertEq(1 ether, bridgeSafeDest.balanceOf(alice), "the alice should have 1 tokens on dest chain");
        assertEq(0, bridgeSafe.balanceOf(alice), "the alice should have 0 tokens on src chain");
        assertEq(address(bridgeSafe).balance, staticFee, "Bridge should have staticFee left");
    }

    function test_ReplayAttackPrevention() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: alice,
            to: user,
            value: 1 ether,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: "",
            repayAddr: address(0)
        });

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"
                ),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridgeSafe.getDomainSeparator(), structHash));

        // Sign the message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);

        // Concatenate v, r, and s into a single signature
        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 4 ether);
        vm.prank(user);
        bridgeSafe.sendMsgPermit{value: 1 ether + staticFee}(transaction, signature);

        // Attempt to replay the same transaction
        vm.prank(user);
        vm.expectRevert("Bridge: invalid signature");
        bridgeSafe.sendMsgPermit{value: 1 ether + staticFee}(transaction, signature);
    }

    function test_InvalidSignature() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(owner);
        bridgeSafe.mint(alice, 1 ether);
        bridgeSafeDest.mint(alice, 1 ether);
        vm.stopPrank();

        // Prepare transaction
        IBridge.Transaction memory transaction = IBridge.Transaction({
            id: bridgeSafe.messageId(),
            from: alice,
            to: address(bridgeSafeDest), // using bridgeSafeDest instead of bridgeSafe, assuming that the both will be same on different chains.
            value: 0,
            srcChainId: block.chainid,
            dstChainId: 2,
            data: abi.encodeWithSignature("transfer(address,uint256)", user, 1 ether),
            repayAddr: address(0)
        });

        transaction.id = 5555; // Set an invalid ID to trigger the revert

        // Generate EIP-712 hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"
                ),
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                keccak256(transaction.data)
            )
        );

        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", bridgeSafe.getDomainSeparator(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, messageHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Fund user and send the transaction
        vm.deal(user, 2 ether);
        vm.prank(user);
        vm.expectRevert("Bridge: invalid signature");
        bridgeSafe.sendMsgPermit{value: staticFee}(transaction, signature);
    }
}
