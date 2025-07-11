// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Bytes.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {ISignalProcessor} from "./SignalProcessor.sol";
import "./BridgeToken.sol";

contract BridgeHashCollision is ReentrancyGuard, Ownable, BridgeToken {
    constructor(address initialOwner, address _signalProcessor) BridgeToken(initialOwner) {
        paused = false;
        signalProcessor = _signalProcessor;
    }

    mapping(bytes32 => bool) public processedMessages;
    uint256 public messageId;

    bool public paused;
    address signalProcessor;
    uint256 public constant MAX_TRANSFER_AMOUNT = 1000000 * 10 ** 18;
    uint256 public staticFee = 0.0001 ether;
    uint256 public msgPacked;

    enum MsgStatus {
        UnProcessed,
        Processed,
        Failed
    }

    mapping(bytes32 => MsgStatus) public msgStatus;

    event TxProcessed(bytes32 messageHash);
    event BridgePaused();
    event BridgeUnpaused();

    function setStaticFee(uint256 fee) external onlyOwner {
        staticFee = fee;
    }

    function sendMsg(address to, uint256 value, uint256 dstChainId, bytes memory data) external payable nonReentrant {
        require(!paused, "Bridge: paused");
        require(value <= MAX_TRANSFER_AMOUNT, "Bridge: amount too large");
        require(msg.value == value + staticFee, "Bridge: insufficient or different value sent");

        uint256 srcChainId = block.chainid;
        address from = msg.sender;
        string memory idString = Strings.toString(messageId++);
        string memory valueString = Strings.toString(value);

        require(srcChainId != dstChainId, "Bridge: source and destination chain IDs must be different");

        // For vuln visuallisation in test
        msgPacked = uint256(bytes32(abi.encodePacked(idString, valueString, from, to, srcChainId, dstChainId, data)));
        // Vulnerable: hash collision possible due to lack of struct typing
        bytes32 messageHash = keccak256(abi.encodePacked(idString, valueString, from, to, srcChainId, dstChainId, data));

        ISignalProcessor(signalProcessor).sendTx(messageHash);

        if (to == address(0) || to == address(this)) {
            if (bytes4(data) != this.transfer.selector) {
                (, uint256 valueToTransfer) = abi.decode(Bytes.slice(data, 4), (address, uint256));
                _burn(from, valueToTransfer);
            }
        }
    }

    function sendMsgPermit(
        address from,
        address to,
        uint256 value,
        uint256 dstChainId,
        bytes memory data,
        bytes memory signature
    ) external payable nonReentrant {
        require(!paused, "Bridge: paused");
        require(value <= MAX_TRANSFER_AMOUNT, "Bridge: amount too large");
        require(msg.value == value + staticFee, "Bridge: insufficient or different value sent");

        uint256 srcChainId = block.chainid;
        string memory idString = Strings.toString(messageId++);
        string memory valueString = Strings.toString(value);

        require(srcChainId != dstChainId, "Bridge: source and destination chain IDs must be different");

        // Vulnerable: hash collision possible due to lack of struct typing
        bytes32 messageHash = keccak256(abi.encodePacked(idString, valueString, from, to, srcChainId, dstChainId, data));

        address signer = ECDSA.recover(messageHash, signature);
        require(signer == from, "Bridge: invalid signature");

        ISignalProcessor(signalProcessor).sendTx(messageHash);

        if (to == address(0) || to == address(this)) {
            if (bytes4(data) != this.transfer.selector) {
                (, uint256 valueToTransfer) = abi.decode(Bytes.slice(data, 4), (address, uint256));
                _burn(from, valueToTransfer);
            }
        }
    }

    function executeMessage(
        uint256 id,
        address from,
        address to,
        uint256 value,
        uint256 srcChainId,
        uint256 dstChainId,
        bytes calldata data
    ) external nonReentrant {
        require(!paused, "Bridge: paused");

        string memory idString = Strings.toString(id);
        string memory valueString = Strings.toString(value);

        bytes32 messageHash = keccak256(abi.encodePacked(idString, valueString, from, to, srcChainId, dstChainId, data));

        require(!processedMessages[messageHash], "Bridge: message already processed");
        require(msgStatus[messageHash] == MsgStatus.UnProcessed, "Bridge: message not initiated");
        require(block.chainid == dstChainId, "Bridge: block.chainid and destination chain IDs must be similar");

        processedMessages[messageHash] = true;
        require(ISignalProcessor(signalProcessor).verifyTx(messageHash), "Bridge: transaction was not verified");

        if (to == address(0) || to == address(this)) {
            if (bytes4(data) == this.transfer.selector) {
                (address toAddr, uint256 val) = abi.decode(data[4:], (address, uint256));
                _transfer(from, toAddr, val);
            } else {
                (, uint256 val) = abi.decode(data[4:], (address, uint256));
                _mint(from, val);
            }
        } else {
            (bool success,) = to.call{value: value}(data);
            require(success, "Bridge: Execution failed");
        }

        msgStatus[messageHash] = MsgStatus.Processed;

        emit TxProcessed(messageHash);
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
