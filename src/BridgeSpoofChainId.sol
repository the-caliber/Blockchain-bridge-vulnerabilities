// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Bytes.sol";
import "./IBridge.sol";
import {ISignalProcessor} from "./SignalProcessor.sol";
import "./BridgeToken.sol";

contract BridgeSpoofChainId is ReentrancyGuard, Ownable, IBridge, EIP712, BridgeToken {
    string private constant SIGNING_DOMAIN = "BridgeSpoofingChainId";
    string private constant SIGNATURE_VERSION = "1";
    mapping(uint256 => bool) public allowedSrcChains;

    constructor(address initialOwner, address _signalProcessor)
        BridgeToken(initialOwner)
        EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION)
    {
        paused = false;
        signalProcessor = _signalProcessor;
    }

    mapping(bytes32 => bool) public processedMessages;
    uint256 public messageId;

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

    bytes32 private constant TRANSACTION_TYPEHASH = keccak256(
        "Transaction(uint256 id,address from,address to,uint256 value,uint256 srcChainId,uint256 dstChainId,bytes data)"
    );

    function setStaticFee(uint256 fee) external onlyOwner {
        staticFee = fee;
    }

    function setAllowedSrcChain(uint256 chainId, bool allowed) external onlyOwner {
        allowedSrcChains[chainId] = allowed;
    }

    function sendMsg(Transaction memory transaction) external payable nonReentrant {
        require(!paused, "Bridge: paused");
        require(transaction.value <= MAX_TRANSFER_AMOUNT, "Bridge: amount too large");
        require(msg.value == transaction.value + staticFee, "Bridge: insufficient or different value sent");
        require(
            transaction.srcChainId != transaction.dstChainId,
            "Bridge: source and destination chain IDs must be different"
        );

        // transaction.srcChainId = block.chainid;
        transaction.from = msg.sender;
        transaction.id = messageId++;

        bytes32 messageHash = keccak256(abi.encode(transaction));

        ISignalProcessor(signalProcessor).sendTx(messageHash);

        if (transaction.to == address(0) || transaction.to == address(this)) {
            // if its not a transfer then only burn on this chain, so tokens can be minted on other.
            // if its transfer then dont burn on this chain, this means, tokens can be transferred to other.
            if (bytes4(transaction.data) != this.transfer.selector) {
                (, uint256 valueToTransfer) = abi.decode(Bytes.slice(transaction.data, 4), (address, uint256));
                _burn(transaction.from, valueToTransfer);
            }
        }

        emit TxInitiated(transaction, messageHash);
    }

    function sendMsgPermit(Transaction memory transaction, bytes memory signature) external payable nonReentrant {
        require(!paused, "Bridge: paused");
        require(transaction.value <= MAX_TRANSFER_AMOUNT, "Bridge: amount too large");
        require(msg.value == transaction.value + staticFee, "Bridge: insufficient or different value sent");

        // transaction.srcChainId = block.chainid;
        transaction.id = messageId++;

        require(
            transaction.srcChainId != transaction.dstChainId,
            "Bridge: source and destination chain IDs must be different"
        );

        bytes32 transactionHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    TRANSACTION_TYPEHASH,
                    transaction.id,
                    transaction.from,
                    transaction.to,
                    transaction.value,
                    transaction.srcChainId,
                    transaction.dstChainId,
                    keccak256(transaction.data)
                )
            )
        );

        address signer = ECDSA.recover(transactionHash, signature);
        require(signer == transaction.from, "Bridge: invalid signature");

        bytes32 messageHash = keccak256(abi.encode(transaction));
        ISignalProcessor(signalProcessor).sendTx(messageHash);

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

        address recipient = transaction.to;
        uint256 amount = transaction.value;
        bytes32 messageHash = keccak256(abi.encode(transaction));

        require(msgStatus[messageHash] == MsgStatus.UnProcessed, "Bridge: message not initiated");
        require(!processedMessages[messageHash], "Bridge: message already processed");
        require(allowedSrcChains[transaction.srcChainId], "Bridge: source chain not allowed");

        processedMessages[messageHash] = true;
        require(ISignalProcessor(signalProcessor).verifyTx(messageHash), "Bridge: transaction was not verified");

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

        msgStatus[messageHash] = MsgStatus.Processed;

        emit TxProcessed(messageHash);
    }

    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function pauseBridge() external onlyOwner {
        paused = true;
        emit BridgePaused();
    }

    function unpauseBridge() external onlyOwner {
        paused = false;
        emit BridgeUnpaused();
    }
}
