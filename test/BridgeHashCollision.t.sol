// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/BridgeHashCollision.sol";
import "../src/IBridge.sol";
import "../src/SignalProcessor.sol";

contract BridgeHashCollisionTest is Test {
    BridgeHashCollision bridge;
    BridgeHashCollision destBridge;
    SignalProcessor signalProcessor;
    address owner = address(0x1);
    address user = address(0x2);
    uint256 staticFee = 0.0001 ether;

    function setUp() public {
        vm.startPrank(owner);
        signalProcessor = new SignalProcessor();
        bridge = new BridgeHashCollision(owner, address(signalProcessor));
        destBridge = new BridgeHashCollision(owner, address(signalProcessor));
        vm.stopPrank();
    }

    function test_sendMsg_hash_collision() public {
        vm.deal(user, 2 ether);
        for (uint256 i = 1; i <= 12; i++) {
            uint256 value = (i == 12) ? 20000000000000000 : 120000000000000000;
            IBridge.Transaction memory transaction = IBridge.Transaction({
                id: bridge.messageId(),
                from: user,
                to: user,
                value: value,
                srcChainId: block.chainid,
                dstChainId: 2,
                data: bytes("0"),
                repayAddr: address(0)
            });

            vm.prank(user);
            bridge.sendMsg{value: transaction.value + staticFee}(
                transaction.to, transaction.value, transaction.dstChainId, transaction.data
            );

            vm.chainId(2);

            // Mimic user's stored ETH on the bridge contract
            vm.deal(address(destBridge), 2 ether);

            if (i == 12) vm.expectRevert("Bridge: message already processed");
            destBridge.executeMessage(
                transaction.id,
                transaction.from,
                transaction.to,
                transaction.value,
                transaction.srcChainId,
                transaction.dstChainId,
                transaction.data
            );

            vm.chainId(transaction.srcChainId);
        }
    }
}
