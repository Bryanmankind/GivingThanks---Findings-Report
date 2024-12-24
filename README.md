# GivingThanks - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Incorrect Verification Check in isVerified Function of CharityRegistry Contract](#H-01)
    - ### [H-02.  Lack of Access Control in updateRegistry Function](#H-02)
- ## Medium Risk Findings
    - ### [M-01. Incorrect Assignment of CharityRegistry Address](#M-01)
    - ### [M-02.  Incorrect Initialization of tokenCounter](#M-02)
- ## Low Risk Findings
    - ### [L-01. Missing Check for Zero Donation in donate Function](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #28

### Dates: Nov 7th, 2024 - Nov 14th, 2024

[See more contest details here](https://codehawks.cyfrin.io/c/2024-11-giving-thanks)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 2
- Medium: 2
- Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. Incorrect Verification Check in isVerified Function of CharityRegistry Contract            



## Summary

The `isVerified` function in the `CharityRegistry` contract contains a critical bug where it incorrectly returns the value from `registeredCharities` rather than `verifiedCharities`. This means that any charity that has been registered, regardless of whether it has been verified, will appear as verified in the system.

## Vulnerability Details

The `isVerified` function currently returns `registeredCharities[charity]`, which checks only if a charity is registered. The function should instead check `verifiedCharities[charity]` to determine if the charity has been verified.

```Solidity
function isVerified(address charity) public view returns (bool) {
    return registeredCharities[charity]; // @audit should call verifiedCharities
}

```

## Impact

Any address that is registered as a charity will appear as verified, even if it has not been verified by the admin. This could lead to unauthorized or unverified charities gaining access to features or interactions intended only for verified charities.

## Tools Used

manual  reviews 

## Recommendations

Modify the `isVerified` function to check `verifiedCharities` instead of `registeredCharities`.



```Solidity
function isVerified(address charity) public view returns (bool) {
    return verifiedCharities[charity];
}

```

## <a id='H-02'></a>H-02.  Lack of Access Control in updateRegistry Function            



## Summary

The `updateRegistry` function in the `GivingThanks` contract is vulnerable due to a lack of access control. Currently, **anyone** can call this function to update the `registry` address, potentially redirecting it to a malicious contract. This can lead to unauthorized changes in the behavior of the contract, especially if the `registry` contract is used for critical validations like charity verifications.

## Vulnerability Details

Missing access control, allowing any user to update the `registry` address.

```Solidity
function updateRegistry(address _registry) public {
    registry = CharityRegistry(_registry);
}

```

## Impact

**Unauthorized Access**: Any user can change the `registry` address, which could redirect the contract's logic to interact with a malicious `CharityRegistry` contract.

* **Potential Exploits**: Attackers could deploy a fake `CharityRegistry` contract, verify unauthorized charities, and exploit the `GivingThanks` contract by minting tokens or manipulating charity verification statuses.

## Tools Used

manual review 

## Recommendations

restrict access to the `updateRegistry` function by adding an `onlyOwner` modifier. This will ensure that only the contract owner can update the `registry` address.



```Solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Caller is not the owner");
    _;
}

function updateRegistry(address _registry) public onlyOwner {
    registry = CharityRegistry(_registry);
}

```

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Incorrect Assignment of CharityRegistry Address            



## Summary

In the `GivingThanks` smart contract, there is an issue in the constructor where the `registry` variable, intended to store the address of the `CharityRegistry` contract, is incorrectly assigned. Instead of using the `_registry` parameter passed during deployment, the contract mistakenly assigns `msg.sender` to the `registry` variable. This results in the contract deployer's address being cast as the `CharityRegistry` contract.

## Vulnerability Details

```Solidity
constructor(address _registry) ERC721("DonationReceipt", "DRC") {
    registry = CharityRegistry(msg.sender);  // Incorrect assignment
    owner = msg.sender;
    tokenCounter = 0;
}

```

## Impact

**Incorrect Registry Assignment**: The contract will treat the deployer's address as the `CharityRegistry`, which is not the intended behavior. This can cause all functions dependent on the `registry` variable  to fail or produce incorrect results.

* **Potential Security Risks**: Since the deployer's address is treated as the registry, the contract could behave unpredictably, especially if the deployer is not a legitimate charity registry contract.

## Tools Used

manula review

## Recommendations

the constructor should assign the `_registry` parameter to the `registry` variable.



```Solidity
constructor(address _registry) ERC721("DonationReceipt", "DRC") {
    registry = CharityRegistry(_registry);  // Correct assignment
    owner = msg.sender;
    tokenCounter = 0;
}

```

## <a id='M-02'></a>M-02.  Incorrect Initialization of tokenCounter            



## Summary

The `tokenCounter` is initialized to `0` in the constructor, which leads to the first minted token having a token ID of `0`. Typically, token IDs should start from `1` for clarity and convention.

## Vulnerability Details

tokenCounter starts at 0 instead of 1

```Solidity
uint256 public tokenCounter;

constructor(address _registry) ERC721("DonationReceipt", "DRC") {
    registry = CharityRegistry(_registry);  
    owner = msg.sender;
    tokenCounter = 0; // @audit should be initialized to 1
}

```

## Impact

**Impact**: The first call to mint a token will use `tokenCounter` value of `0`, which is usually avoided in many ERC721 implementations as it could cause confusion or conflicts in downstream applications.

## Tools Used



## Recommendations

Update the constructor to set `tokenCounter` to `1` instead of `0`.



```Solidity
constructor(address _registry) ERC721("DonationReceipt", "DRC") {
    registry = CharityRegistry(_registry);  
    owner = msg.sender;
    tokenCounter = 1; // Initialize to 1
}

```


# Low Risk Findings

## <a id='L-01'></a>L-01. Missing Check for Zero Donation in donate Function            



## Summary

The `donate` function does not have a check to ensure that `msg.value` (the Ether sent by the user) is greater than zero. This means that users can send a donation of `0 ETH` and still receive an NFT, which can lead to abuse of the system, where users may mint NFTs without actually making any contribution.

## Vulnerability Details

In this code, there is no check on `msg.value`. Therefore, even if `msg.value` is zero, the `_mint` function will still be called, and the user will receive an NFT without actually donating any Ether.

```Solidity
function donate(address charity) public payable {
    require(registry.isVerified(charity), "Charity not verified");
  // @audit. no check for zero  eth transfer 
    (bool sent, ) = charity.call{value: msg.value}("");
    require(sent, "Failed to send Ether");

    _mint(msg.sender, tokenCounter);

    // Create metadata for the tokenURI
    string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
    _setTokenURI(tokenCounter, uri);

    tokenCounter += 1;
}

```

## Impact

The user will receive an NFT with zero value, and the charity does not receive any donation.



## Tools Used

manual review 

## Recommendations

Add a `require` statement to ensure that `msg.value` is greater than zero. Here’s the modified code with the fix:

```Solidity
function donate(address charity) public payable {
    require(registry.isVerified(charity), "Charity not verified");
    require(msg.value > 0, "Donation amount must be greater than zero"); // Added check for non-zero donation

    (bool sent, ) = charity.call{value: msg.value}("");
    require(sent, "Failed to send Ether");

    tokenCounter += 1; // Increment tokenCounter before minting

    // Use safeMint instead of mint for better security
    _safeMint(msg.sender, tokenCounter);

    // Create metadata for the tokenURI
    string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
    _setTokenURI(tokenCounter, uri);

    emit DonationReceived(msg.sender, charity, msg.value, tokenCounter); // Optional: Emit an event
}

```



