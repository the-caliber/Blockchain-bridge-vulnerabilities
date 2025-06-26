// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
// import "@openzeppelin/contracts/access/Ownable.sol"; // the BridgeToken contract already inherits Ownable
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./IBridge.sol";
import "../src/BridgeToken.sol";
import {ISignalProcessor} from "./SignalProcessor.sol";
import "@openzeppelin/contracts/utils/Bytes.sol";

contract BridgeSignatureReplay is ReentrancyGuard, IBridge, BridgeToken {
    // Add constructor to initialize Ownable
    constructor(address initialOwner, address _signalProcessor) BridgeToken(initialOwner) {
        paused = false;
        signalProcessor = _signalProcessor;
    }

    mapping(bytes32 => bool) public processedMessages;
    uint256 public messageId; // Global variable to track message IDs

    // Chain IDs
    uint256 public srcChainId;
    uint256 public dstChainId;

    bool public paused;
    address signalProcessor;
    uint256 public constant MAX_TRANSFER_AMOUNT = 1000000 * 10 ** 18;
    uint256 public staticFee = 0.0001 ether;

    enum MsgStatus {
        UnProcessed,
        Processed,
        Failed
    }

    mapping(bytes32 => MsgStatus) public msgStatus;

    function sendMsg(Transaction memory transaction) external payable nonReentrant {
        require(!paused, "Bridge: paused");
        require(transaction.value <= MAX_TRANSFER_AMOUNT, "Bridge: amount too large");
        require(msg.value == transaction.value + staticFee, "Bridge: insufficient or different value sent");
        require(
            transaction.srcChainId != transaction.dstChainId,
            "Bridge: source and destination chain IDs must be different"
        );

        transaction.srcChainId = block.chainid;
        transaction.from = msg.sender;
        transaction.id = messageId++;

        bytes32 transactionHash = keccak256(abi.encode(transaction)); // Generate a unique hash for the transaction

        ISignalProcessor(signalProcessor).sendTx(transactionHash); // Call the processService function to signal the transaction

        if (transaction.to == address(0) || transaction.to == address(this)) {
            // if its not a transfer then only burn on this chain, so tokens can be minted on other.
            // if its transfer then dont burn on this chain, this means, tokens can be transferred to other.
            if (bytes4(transaction.data) != this.transfer.selector) {
                (, uint256 valueToTransfer) = abi.decode(Bytes.slice(transaction.data, 4), (address, uint256));
                _burn(transaction.from, valueToTransfer);
            }
        }

        emit TxInitiated(transaction, transactionHash);
    }

    function sendMsgPermit(Transaction memory transaction, uint8 v, bytes32 r, bytes32 s)
        external
        payable
        nonReentrant
    {
        require(!paused, "Bridge: paused");
        require(transaction.value <= MAX_TRANSFER_AMOUNT, "Bridge: amount too large");
        require(msg.value == transaction.value + staticFee, "Bridge: insufficient or different value sent");
        require(
            transaction.srcChainId != transaction.dstChainId,
            "Bridge: source and destination chain IDs must be different"
        );

        // transaction.srcChainId = block.chainid; // Shows cross chain signature replay vulnerability. similar to the problems arises because of not using domain separator in EIP712, which uses the chainId as part of the hash.
        // transaction.id = messageId++; // Shows signature replay vulnerability.

        bytes32 transactionHash = keccak256(abi.encode(transaction)); // Generate a unique hash for the transaction
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", transactionHash));

        // Recover the signer from v, r, s and ensure it matches transaction.from
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer == transaction.from, "Bridge: invalid signature");

        ISignalProcessor(signalProcessor).sendTx(transactionHash); // Call the processService function to signal the transaction

        if (transaction.to == address(0) || transaction.to == address(this)) {
            // if its not a transfer then only burn on this chain, so tokens can be minted on other.
            // if its transfer then dont burn on this chain, this means, tokens can be transferred to other.
            if (bytes4(transaction.data) != this.transfer.selector) {
                (, uint256 valueToTransfer) = abi.decode(Bytes.slice(transaction.data, 4), (address, uint256));
                _burn(transaction.from, valueToTransfer);
            }
        }

        emit TxInitiated(transaction, transactionHash);
    }

    function executeMessage(Transaction calldata transaction) external nonReentrant {
        require(!paused, "Bridge: paused");

        address recipient = transaction.to; // Assuming `to` is the recipient address
        address repay = transaction.repayAddr; // Assuming `to` is the recipient address
        uint256 amount = transaction.value; // Assuming `value` is the amount
        bytes32 messageHash = keccak256(abi.encode(transaction)); // Generate a unique hash for the transaction

        require(msgStatus[messageHash] == MsgStatus.UnProcessed, "Bridge: message not initiated");
        require(!processedMessages[messageHash], "Bridge: message already processed");

        // processedMessages[messageHash] = true;
        require(ISignalProcessor(signalProcessor).verifyTx(messageHash), "Bridge: transaction was not verified"); // Call the processService function to verify the transaction

        // Additional logic can be added here to handle `transaction`
        if (transaction.to == address(0) || transaction.to == address(this)) {
            if (bytes4(transaction.data) == this.transfer.selector) {
                (address to, uint256 value) = abi.decode(transaction.data[4:], (address, uint256));
                _transfer(transaction.from, to, value);
            } else {
                // Burn on SRC chain, mint on DST(this) chain
                (, uint256 value) = abi.decode(transaction.data[4:], (address, uint256));
                _mint(transaction.from, value);
            }
        } else {
            (bool success,) = recipient.call{value: amount}(transaction.data);
            require(success, "Bridge: Execution failed");
        }

        // msgStatus[messageHash] = MsgStatus.Processed;

        emit TxProcessed(messageHash);
    }

    // ETH removal function

    // Pausing and unpausing the bridge

    function pauseBridge() external onlyOwner {
        paused = true;
        emit BridgePaused();
    }

    function unpauseBridge() external onlyOwner {
        paused = false;
        emit BridgeUnpaused();
    }
}
