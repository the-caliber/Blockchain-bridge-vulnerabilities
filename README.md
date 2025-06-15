## Bridge vulnerabilities

**This project shows blockchain smart contract bridge vulnerabilities.**

It currently shows some vulnerabilities from [SCSVS v2](https://github.com/ComposableSecurity/SCSVS/blob/master/2.0/0x200-Components/0x205-C5-Bridge.md):

> The smart contracts used in the project are not audited and are vulnerable. Not to use in the production.

## **About:**  
- The contract uses the EIP-712 standard.
- Integrates an external signal processor.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.

**BridgeSignatureReplay**
- Does not use the EIP-712 standard.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.
- Demonstrates message replay, signature replay, and cross-chain signature replay attacks.

**BridgeSpoofChainId**
- The contract uses the EIP-712 standard.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.
- Demonstrates chain ID spoofing in the bridge implementation.

**BridgeHashCollision**
- Does not use the EIP-712 standard.
- Allows burning tokens on the source chain and minting the same amount on the destination chain.
- Allows transferring tokens on the destination chain to a new address on the destination chain itself.
- Demonstrates hash collision.

---
## **Vuln Explanation**:  
ToDo: *Add explanation for every test/vulnerabilities.*

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
