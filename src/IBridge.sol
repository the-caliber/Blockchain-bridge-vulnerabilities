// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBridge {
    // Structs
    struct Transaction {
        uint256 id; // Unique identifier for the transaction
        address from; // Address of the sender
        address to; // Address of the recipient
        uint256 value; // Amount of tokens to be transferred
        uint256 srcChainId; // Source chain ID where the transaction originated
        uint256 dstChainId; // Destination chain ID where the transaction is intended
        bytes data; // Additional data or payload for the transaction
        address repayAddr;
    }

    // Variables
    // ...

    // Events
    event TxInitiated(Transaction transaction, bytes32 msgHash);

    event TxProcessed(bytes32 msgHash);

    event TokenAdded(address indexed token);
    event BridgePaused();
    event BridgeUnpaused();

    // Functions
    function sendMsg(Transaction memory transaction) external payable;
    function executeMessage(Transaction calldata transaction) external;
    function pauseBridge() external;
    function unpauseBridge() external;
}
