## Bridge vulnerabilities

**This project shows blockchain smart contract bridge vulnerabilities.**

It shows some vulnerabilities from [SCSVS v2](https://github.com/ComposableSecurity/SCSVS/blob/master/2.0/0x200-Components/0x205-C5-Bridge.md):

> The smart contracts used in the project are not audited and are vulnerable. Not to use in the production.

**About**:  
**BridgeSendTokenSafe** smart contract facilitates cross-chain token transfers. It acts as a bridge, allowing users to send tokens from one blockchain to another. The contract uses EIP-712 standard, integrates an external signal processor for message verification, and includes mechanisms to burn tokens on the source chain and mint or transfer them on the destination chain.

**BridgeSignatureReplay** does not follow the EIP-712 standard. it shows message replay, signature replay and cross-chain signature replay attack.

**BridgeSpoofChainId** does not follow the EIP-712 standard. it shows chain id spoofing in the bridge implementation.

**Vuln Explanation**:  
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

