## Bridge vulnerabilities

**This project shows blockchain smart contract bridge vulnerabilities.**

It currently shows some vulnerabilities from [SCSVS v2](https://github.com/ComposableSecurity/SCSVS/blob/master/2.0/0x200-Components/0x205-C5-Bridge.md):

> [!WARNING]
> The smart contracts used in the project are not audited and are vulnerable. Not to use in the production.

## **About:**  
**[BridgeSafeTokenSend](src/BridgeSafeTokenSend.sol)**
- The contract uses the EIP-712 standard.
- Integrates an external signal processor.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.

**[BridgeSignatureReplay](src/BridgeSignatureReplay.sol)**
- Does not use the EIP-712 standard.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.
- Demonstrates message replay, signature replay, and cross-chain signature replay attacks.

**[BridgeSpoofChainId](src/BridgeSpoofChainId.sol)**
- The contract uses the EIP-712 standard.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.
- Demonstrates chain ID spoofing in the bridge implementation.

**[BridgeHashCollision](src/BridgeHashCollision.sol)**
- Does not use the EIP-712 standard.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.
- Demonstrates hash collision.

---
## **Vulnerabilities Explanation**:  
1. [**Intro & Part 1.**](https://www.calibersec.com/blockchain-bridge-security-intro-part-1/)  
    - Overview  
    - Vulnerabilities:  
        - Message replay  
        - Signature replay

2. [**Part 2.**](https://www.calibersec.com/blockchain-bridge-security-part-2/)  
    - Cross chain signature replay
    - Variations of signature replay

3. [**Part 3.**](https://www.calibersec.com/blockchain-bridge-security-part-3/)
    - Arbitrary call execution

4. [**Part 4.**](https://www.calibersec.com/blockchain-bridge-security-part-4/)
    - Chain id spoofing
    - Hash collision
    - Lack of signature expiry check

## Usage

### Build

```shell
$ forge build
```

### Test
```shell
$ forge test # run all tests.
```

```shell
$ forge test --mc <test_contract_name> # run specific test file.
```
---
