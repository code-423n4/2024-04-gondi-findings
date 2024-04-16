### Low-01 Unnecessary code - block.chainid will always equal INITIAL_CHAIN_ID due to constructor
**Instances(1)**
In src/lib/loans/BaseLoan.sol, `DOMAIN_SEPARATOR()` checks whether block.chainid==INITIAL_CHAIN_ID. This control flow is unnecessary because the [constructor](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/BaseLoan.sol#L125C9-L125C42) will ensure that `INITIAL_CHAIN_ID = block.chainid;`.
```solidity
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : _computeDomainSeparator();
    }
```
Recommendations:
Simply return INITIAL_DOMAIN_SEPARATOR

### Low-02 Incorrect comment - The nested struct `Tranche` doesn't have Source[] field.
**Instances(1)**
In src/lib/utils/Hash.sol, the [comment for _MULTI_SOURCE_LOAN_HASH](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/Hash.sol#L25) says `// keccak256("Loan(address borrower,uint256 nftCollateralTokenId,address nftCollateralAddress,address principalAddress,uint256 principalAmount,uint256 startTime,uint256 duration,Tranche[] tranche)Tranche(uint256 floor,uint256 principalAmount,Source[] source)Source(uint256 loanId,address lender,uint256 principalAmount,uint256 accruedInterest,uint256 startTime,uint256 aprBps)")`

This is incorrect, because `Tranche` doens't contain `Source[] source` field.
```solidity
//src/interfaces/loans/IMultiSourceLoan.sol
    struct Tranche {
        uint256 loanId;
        uint256 floor;
        uint256 principalAmount;
        address lender;
        uint256 accruedInterest;
        uint256 startTime;
        uint256 aprBps;
    }
``` 
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/interfaces/loans/IMultiSourceLoan.sol#L101-L108)
Recommendations:
Change the comment for _MULTI_SOURCE_LOAN_HASH per correct Tranche fields.

### Low-03  _MULTI_SOURCE_LOAN_HASH has an incorrect typeHash value 
**Instances(1)**
The current typeHash value of _MULTI_SOURCE_LOAN_HASH in src/lib/utils/Hash.sol is incorrect.
```solidity

    // keccak256("Loan(address borrower,uint256 nftCollateralTokenId,address nftCollateralAddress,address principalAddress,uint256 principalAmount,uint256 startTime,uint256 duration,Tranche[] tranche)Tranche(uint256 floor,uint256 principalAmount,Source[] source)Source(uint256 loanId,address lender,uint256 principalAmount,uint256 accruedInterest,uint256 startTime,uint256 aprBps)")
|>    bytes32 private constant _MULTI_SOURCE_LOAN_HASH =
        0x2e1ab3e8bcbe8abaf7ffbff77233ab3db94e0419d3c3d4874e03fad8918c94f0;
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/Hash.sol#L25)

This typeHash value is based on keccak256 of incorrect struct field. Note that `Source[] source` field doesn't exist in [struct Tranche](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/interfaces/loans/IMultiSourceLoan.sol#L101).

I used a remixIde test to prove the hardcoded typeHash value is per the incorrect comment, but didn't have time to generate the correct typeHash. See test:
```solidity
pragma solidity ^0.8.0;

contract HashGenerator {
    function generateHash() public pure returns (bytes32) {
return keccak256("Loan(address borrower,uint256 nftCollateralTokenId,address nftCollateralAddress,address principalAddress,uint256 principalAmount,uint256 startTime,uint256 duration,Tranche[] tranche)Tranche(uint256 floor,uint256 principalAmount,Source[] source)Source(uint256 loanId,address lender,uint256 principalAmount,uint256 accruedInterest,uint256 startTime,uint256 aprBps)");
    }
}
```
Note that an incorrect typeHash can potentially cause compatibility issue with other on-chain or off-chain flows that use the correct hashing methods.
Recommendations:
Regenerate hash per correct struct fields.


### Low-04 Missing non-reentrant modifier
**Instances(1)**
In src/lib/loans/MultiSourceLoan.sol, all refinance flows have non-reentrant modifier except for refinancePartial.

```solidity
    function refinancePartial(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan
    ) external returns (uint256, Loan memory) {
...
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L235-L237)
Recommendations:
Consider adding non-reentrant modifier.

### Low-05 Duplicated trancheIndexes not checked in `refinancePartial()`
**Instances(1)**
In src/lib/loans/MultiSourceLoan.sol, refinancePartial(), lender will input array of tracheIndexes in ` RenegotiationOffer calldata _renegotiationOffer` [which should correspond to existing loan tranches](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L258-L262).

However, there are no sufficient check to ensure _renegotiationOffer.tranchIndex will not contain duplicated indexes. Note that refinancePartial() allows a subset of existing loan tranches to be updated, which means [_renegotiationOffer.tranchIndex.length check](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L661) will not prevent duplicates.

If lender input duplicated trancheIndex in `_renegotiationOffer()`, there will be [duplicated token transfer](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L636-L637), lender might lose funds.

Recommendations:
Consider adding check to prevent duplicated trancheIndexes to be passed in ` RenegotiationOffer calldata _renegotiationOffer`.

### Low-06  Missing dynamic array input validation in LoanManger::addCallers
**Instances(1)**
In src/lib/loans/LoanManager.sol, addCallers[] will iterate through each _callers input but doesn't check if _callers.length == getPendingAcceptedCallers.length.

When _callers.length < getPendingAcceptedCallers. length, some pending callers are not missed.
```solidity
//src/lib/loans/LoanManager.sol
    function addCallers(PendingCaller[] calldata _callers) external onlyOwner {
...
        PendingCaller[] memory pendingCallers = getPendingAcceptedCallers;
        for (uint256 i = 0; i < _callers.length;) {
            PendingCaller calldata caller = _callers[i];
...
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L80-L82)

Recommendations:
Consider adding a check to ensure _callers.length == getPendingAcceptedCallers.length.

### Low-07 Consider resetting getPendingAcceptedCallersSetTime to max after adding callers.
**Instances(1)**
Current two-step addCallers flow [will not reset getPendingAcceptedCallersSetTime back to `type(uint256).max`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L96).

In addCallers(), at the end of the call, consider resetting getPendingAcceptedCallersSetTime to `type(uint256).max` to prevent resetting the same caller multiple times.

Recommendations:
consider resetting getPendingAcceptedCallersSetTime to `type(uint256).max` at the end of addCallers().

### Low-08 Unused imports 
**Instances(3)**
(1)
src/lib/LiquidationDistributor.sol
```
import "./loans/WithLoanManagers.sol";
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/LiquidationDistributor.sol#L13)
(2)
src/lib/loans/BaseLoan.sol
```
import "./WithLoanManagers.sol";
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/BaseLoan.sol#L15)
(3)
src/lib/utils/WithProtocolFee.sol
```
import "../loans/WithLoanManagers.sol";
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/WithProtocolFee.sol#L7C1-L7C40)
Recommendations:
Remove unused imports

### Low-09 baseInterestAllocator risks being set as a malicious contract address due to vuln. implementations.
**Instances(1)**
In src/lib/pools/Pool.sol, setting `getBaseInterestAllocator` address with confirmBaseInterestAllocator() is not access-controlled and can be set to any address if current `getBaseInterestAllocator` is 0 value.

This requires `confirmBaseInterestAllocator()` to be called atomically with contract deployment to prevent malicious front-running and setting a malicious `getBaseInterestAllocator` address.

Recommendations:
Either consider setting `getBaseInterestAllocator` in the constructor to prevent malicious front-running.

### Low-10 Incorrect comments - netPoolFraction is in PRINCIPAL_PRECISION, not bps.
**Instances(1)**
In src/lib/pools/Pool.sol, code comments says struct QueueAccounting.netPoolFraction is in bps precision. This is incorrect, netPoolFraction and thisQueueFraction are both in PRINCIPAL_PRECISION.

```solidity
//src/lib/pools/Pool.sol
    /// @param thisQueueFraction Fraction of this queue in `PRINCIPAL_PRECISION`
    /// @param netPoolFraction Fraction that still goes to the pool on repayments/liquidations in bps`. //@audit netPoolFraction is in `PRINCIPAL_PRECISION`, not bps
    struct QueueAccounting {
        uint128 thisQueueFraction;
        uint128 netPoolFraction;
    }

```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L68)

Recommendations:
Change the code comments.

### Low-11 Typos
**Instances(1)**
In src/lib/pools/Pool.sol, deployWithdrawalQueue() comments contains a typo: outsanding -> outstanding.
```solidity
   function deployWithdrawalQueue() external nonReentrant {
   ...
           //@audit  Typo - outstaning -> outstanding
        /// @dev We move outstaning values from the pool to the queue that was just deployed.
```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L375)
Recommendations:
Correct the typo.

### Low-12 Unnecessary code - duplicated checks in placeBid()
**Instances(1)**
In src/lib/AuctionLoanLiquidator.sol, placeBid() contains [duplicated checks](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L230-L231) that are already [performed in  _placeBidChecks() hooks](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L332-L333).

```solidity
    function placeBid(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        external
        nonReentrant
        returns (Auction memory)
    {
...
|>        if (_bid == 0 || (currentHighestBid.mulDivDown(_BPS + MIN_INCREMENT_BPS, _BPS) >= _bid)) {
            revert MinBidError(_bid);
        }

```
(https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L230C1-L232C10)
Recommendations:
Delete duplicated checks.
