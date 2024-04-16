# Analysis - Gondi Contest

## System Overview
### What is Gondi
Gondi is a decentralized non-custodial NFT lending protocol that offers the most flexible and capital efficient primitive. Gondi loans allows borrowers to access liquidity and obtain the best marginal rate when available as well as allow lenders to earn yield on their capital with the flexibility of entering and exiting their position any moment without affecting borrowers' loans.

In new version Gondi V3 loan offers are submitted from both protocol pools as well as peers market participants creating deep liquidity as well as precise risk pricing.
### Overview
The diagram below presented the interaction of Gondi contracts.
![Imgur](https://i.imgur.com/2kgfTW8.png)

The Gondi contracts can be divided into three sets:

- **Loan**: This is the core of the Gondi protocol and includes the main logic for the Gondi P2P NFT lending protocol.
    - **BaseLoan**: Manages basic loan offer and renegotiation offer information. Since the offer is signed off-chain, this contract contains the logic needed to cancel the offer on-chain.
    - **PurchaseBundler**: Allows users to bundle a purchase and take out a loan in a single transaction. For example, if there's an NFT for sale at 20e and an outstanding loan offer for 10e, a user only needs 10e to start, instead of needing 20e to buy it first and then take out a loan for 10e.
    - **CallbackHandler**: Whitelists and checks callback return data. This contract handles calls to `PurchaseBundler`.
    - **LiquidationHandler**: Includes the function `_liquidateLoan()` to handle loan liquidation cases (one lender & multiple lenders).
    - **MultiSourceLoan**: All the contracts mentioned above are composed into the MultiSourceLoan. This contract, which will be deployed, contains all the logic of these abstract contracts above.
- **Pool**: Gondi Pools are simply ERC4626, allowing lenders to deposit liquidity. This Pool will act as the lender in the main MultiSourceLoan contract.
    - **PoolOfferHandler**: Whitelists loan terms for different collections, durations, APRs, etc. For any given offer, it checks that the requested principal is below the max allowed, the APR is at least the minimum defined, and the max senior repayment is below the max allowed.
    - **WithdrawalQueue**: Pools use WithdrawalQueues to manage fund withdrawals. Each withdrawal request is represented by an NFT (which can be traded, borrowed against, etc).
    - **FeeManager**: A protocol fee contract, contains a function to calculate the fee when a loan is repaid or liquidated.
    - **AaveUsdcBaseInterestAllocator**: When funds are not deployed to any loan, they could be deposited in third-party protocols to earn base interest. In the case of a USDC pool, it will be deposited in the Aave protocol.
    - **LidoEthBaseInterestAllocator**: If the asset is WETH, it will be deposited in Lido to earn interest.
- **Liquidator**: Contains the logic to handle liquidation when the borrower cannot meet the repayment deadline.
    - **AuctionLoanLiquidator**: Implements core functionalities to run an auction for the NFT collateral. It receives an NFT to be auctioned when a loan defaults.
    - **AuctionWithBuyoutLoanLiquidator**: Extends `AuctionLoanLiquidator` but adds a feature to allow the main lender to buyout the NFT. The main lender, defined as the lender with the largest tranche in the loan, will need to repay other lenders' principal plus interest to receive the NFT.
    - **LiquidationDistributor**: Distributes the received funds after an auction is settled to lenders. Distributions follow a seniority-based waterfall system, covering the principal and accrued interest of the senior tranche before repaying the principal of the next tranche in seniority.


## Approach taken in evaluating the codebase
### Time spent on this audit: 8 days (Full duration of the contest)

Day 1
- Reading the documentation provided in Gitbook

Day 2-3

- Understanding and noting down the logical scope (which contracts will be deployed, which is inherited by other contracts)
- Review utils contracts, contracts with less logic and will be inherited by other contracts like `/utils`, AddressManager, InputChecker, Multicall, UserVault,...

Day 4-5

- Review core logic of `/loan` including `BaseLoan`, `MultiSourceLoan`, `CallbackHandler` and `PurchaseBundler`.

Day 6-7
- Review core logic of `/pools` including `Pool`, `PoolOfferHandler`, `WithdrawalQueue`.
- Review the interaction of Pool with MultiSourceLoan through LoanManager

Day 8
- Writing reports

## Architecture Recommendations

### Unique Features

- Gondi Pool: This feature allows anyone to access yield-bearing assets by simply depositing WETH or USDC into Gondi Pools. The core loan is P2P, so introducing a Pool enables users with less capital and time to participate in the protocol.
- Multiple Tranches: This feature allows one NFT to draw liquidity from multiple lender offers.

### Comparisons with Existing Patterns

- Gondi is similar to another P2P NFT lending protocol I've audited, Particle. Both protocols allow borrowers to take a loan using NFT as collateral and also enable refinancing of existing loans. However, Gondi is more complex, introducing additional features as described above.

## Centralization Risks

### Involved Actors and Their Roles

- The primary trust assumption in the contract is the owner role in all contracts. However, core parameters cannot be changed immediately and require the owner's approval.
- For all two-step parameter change processes, the contract will always use the input parameters of the caller in the "confirm" step to modify variables. Sometimes, only the owner can call these "confirm" functions, but at other times they are open to everyone. As shown in some HM reports, there are issues with these functions.

## Resources used to gain deeper context on the codebase
- Official documentation: https://app.gitbook.com/o/4HJV0LcOOnJ7AVJ77p8e/s/W2WSJrV6PSLWo4p8vIGq/
- Inline comments in codebase
- Previous audit reports: https://app.gitbook.com/o/4HJV0LcOOnJ7AVJ77p8e/s/W2WSJrV6PSLWo4p8vIGq/security-and-audits

## Mechanism Review

### Permissionless Refinance & Renegotiation

- In Gondi, lenders can refinance any existing loans in the protocol in a permissionless manner. This means they can refinance any outstanding loan, without the borrower's action, by reducing the loan's APR by at least 5%. Refinancing can occur at any time while the loan is outstanding and not locked. However, refinancing is triggered only by the lender and doesn't require the borrower's acceptance.
- The `ImprovementMinimum` is a useful factor to protect against spamming issues. Without a minimum, attackers could spam refinance loans with only a `1 wei` increase in the principal token or increase the loan duration by one second, making it impossible for others to refinance.
- This mechanism creates a fair and open market for all lenders to offer the best liquidity terms to the borrower. However, it may be challenging for typical users to keep up with and use the protocol. Lenders must monitor their open loans regularly to ensure their loan is still active and their funds are being utilized.

### Liquidation Auction

- Defaulted loans with two or more tranches go through an auction process. The senior tranche lender has priority over more junior tranches. Distributions follow a waterfall from most senior first to most junior last. Distributions first cover the principal and accrued interest of the senior tranche before repaying the principal of the next tranche in seniority.
- The seniority of a tranche is simply its position in the `tranche` list in `Loan`. The protocol allows lenders to specify their preferred position when submitting a loan offer through the `maxSeniorRepayment` and `principalAmount`.
    **Example**: `[-----amount from offer A--------, --------amount from offer B ---------,]`
    Looking now at offer B
    - `maxSeniorRepayment` Maximum amount of principal+max interest (calculated as the apr at the duration of the loan) from other offers that can be placed ahead of offer B. In other words, A < maxSeniorRepayment
    - `principalAmount` Max amount of principal a loan can have up to offer B has been filled. In other words, A+B < principalAmount


### Gondi Pool
- Gondi Pools is simply a ERC4626, lenders can deposit liquidity to this Pool and this Pool will be the lender in the main MultiSourceLoan contract.
- Gondi Pools are greatly beneficial for lenders who lack the required knowledge or time to actively manage their open loans.
- Some NFTs may have high values, so less capital lenders can also participate in the protocol through Gondi Pools.


## Systemic Risks/Architecture-Level Weak Spots and Their Mitigation Strategies

- Missing Input Validation: Some structures serve multiple purposes. For instance, `RenegotiationOffer` is used in `refinanceFull()`, `refinancePartial()`, and `addNewTranche()`. However, there's no validation implemented to ensure that the structure only contains the necessary data. Specifically, `refinanceFull()` doesn't check if the tranche list is empty. Generally, the protocol lacks sufficient input validation, leading to numerous high-risk issues.
- Another issue related to shared structures is that borrower/lender signatures for these structures will be identical. This occurs even if they intend to call only one function. Since the structure data is shared, the caller could use the signature to invoke other functions.
- The two-step process for changing certain parameters is inconsistent. Some functions are only owner-based, while others are permissionless. These functions typically use the input provided in the "confirm" call to update the state variables, but they don't always verify whether it matches the values in the "pending" call.

### Time spent:
70 hours