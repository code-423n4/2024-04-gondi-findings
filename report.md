---
sponsor: "Gondi"
slug: "2024-04-gondi"
date: "2024-07-25"
title: "Gondi Invitational"
findings: "https://github.com/code-423n4/2024-04-gondi-findings/issues"
contest: 361
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Gondi smart contract system written in Solidity. The audit took place between April 8 — April 16, 2024.

Following the C4 audit, 3 wardens ([bin2chen](https://code4rena.com/@bin2chen), [minhquanym](https://code4rena.com/@minhquanym) and [oakcobalt](https://code4rena.com/@oakcobalt)) reviewed the mitigations for all identified issues; the [mitigation review report](#mitigation-review) is appended below the audit report.

Additionally, a follow up Invitational audit was performed on the codebase. The final report can be viewed [here](https://github.com/code-423n4/2024-06-gondi-findings/blob/main/report.md).

## Wardens

In Code4rena's Invitational audits, the competition is limited to a small group of wardens; for this audit, 5 wardens contributed reports:

  1. [bin2chen](https://code4rena.com/@bin2chen)
  2. [minhquanym](https://code4rena.com/@minhquanym)
  3. [oakcobalt](https://code4rena.com/@oakcobalt)
  4. [zhaojie](https://code4rena.com/@zhaojie)
  5. [erebus](https://code4rena.com/@erebus)

This audit was judged by [0xA5DF](https://code4rena.com/@0xA5DF).

Final report assembled by [thebrittfactor](https://twitter.com/brittfactorC4).

# Summary

The C4 analysis yielded an aggregated total of 37 unique vulnerabilities. Of these vulnerabilities, 17 received a risk rating in the category of HIGH severity and 20 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 3 reports detailing issues with a risk rating of LOW severity or non-critical. There was also 1 report recommending gas optimizations.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Gondi repository](https://github.com/code-423n4/2024-04-gondi), and is composed of 28 smart contracts written in the Solidity programming language and includes 3669 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# High Risk Findings (17)

## [[H-01] Merging tranches could make `_loanTermination()` accounting incorrect ](https://github.com/code-423n4/2024-04-gondi-findings/issues/69)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/69), also found by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/12)*

In the `Pool` contract, when a loan is repaid or liquidated, a call to the Pool is made for accounting. The `_loanTermination()` function is eventually invoked. This function uses the `loanId` to determine the withdrawal queue to which the loan belongs. If the loan was issued after the last queue, it belongs entirely to the pool, and `_outstandingValues` is updated. If not, it updates the queue accounting, queue outstanding values, `getTotalReceived` and `getAvailableToWithdraw`.

```solidity
function _loanTermination(
    ...
) private {
    uint256 pendingIndex = _pendingQueueIndex;
    uint256 totalQueues = getMaxTotalWithdrawalQueues + 1;
    uint256 idx;
    /// @dev oldest queue is the one after pendingIndex
    uint256 i;
    for (i = 1; i < totalQueues;) {
        idx = (pendingIndex + i) % totalQueues;
        if (getLastLoanId[idx][_loanContract] >= _loanId) {
            break;
        }
        unchecked {
            ++i;
        }
    }
    /// @dev We iterated through all queues and never broke, meaning it was issued after the newest one.
    if (i == totalQueues) {
        _outstandingValues =
            _updateOutstandingValuesOnTermination(_outstandingValues, _principalAmount, _apr, _interestEarned);
        return;
    } else {
        uint256 pendingToQueue =
            _received.mulDivDown(PRINCIPAL_PRECISION - _queueAccounting[idx].netPoolFraction, PRINCIPAL_PRECISION);
        getTotalReceived[idx] += _received;
        getAvailableToWithdraw += pendingToQueue;
        _queueOutstandingValues[idx] = _updateOutstandingValuesOnTermination(
            _queueOutstandingValues[idx], _principalAmount, _apr, _interestEarned
        );
    }
}
```

However, the `mergeTranches()` function is permissionless and only requires the merged tranches to be contiguous. Once tranches are merged, the `loanId` of the new tranche changes, which can lead to incorrect accounting in the `Pool`.

### Proof of Concept

Consider the following scenario:

1. A borrower opens a loan and takes liquidity from multiple offers of the same Pool. The loan has the parameters `loanId = 100`, with two tranches, both having `lender = pool_address`.
2. In the Pool, assume `getLastLoanId[1][loan] = 100`, indicating that queue index 1 points to the latest loanId in the `loan` contract.
3. An attacker calls `mergeTranches()` to merge the two tranches of `loanId = 100` with the same lender, which is the pool address. The new `newLoanId = 101` is used in the new tranche.
4. Now, when the loan is repaid, the `_loanTermination()` function is invoked with `_loanId = 101`. The loop returns `i == totalQueues`, making the loan belong entirely to the pool, while it should belong to withdrawal queue index 1.

[MultiSourceLoan.sol#L1132-L1140](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L1132-L1140)

```solidity
tranche[_minTranche] = IMultiSourceLoan.Tranche(
    _newLoanId, // @audit can be used to change loanId
    _loan.tranche[_minTranche].floor,
    principalAmount,
    lender,
    accruedInterest,
    startTime,
    cumAprBps / principalAmount
);
```

### Recommended Mitigation Steps

Limit the ability to call `mergeTranches()` directly to lenders only.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/69#event-12543124405)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Only tranche lender can call `mergeTranches` so it assumes the responsibility.

**Status:** Mitigation confirmed. Full details in reports from [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/50) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/2).

***

## [[H-02] Division before multiplication could lead to users losing 50% in `WithdrawalQueue`](https://github.com/code-423n4/2024-04-gondi-findings/issues/67)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/67)*

In the `_getAvailable()` function, the calculation performs division before multiplication, which could result in precision loss. The consequence is that users may not be able to withdraw the amount they should receive, leaving some funds locked in the `WithdrawalQueue`.

```solidity
// @audit division before multiplication
function _getAvailable(uint256 _tokenId) private view returns (uint256) {
    return getShares[_tokenId] * _getWithdrawablePerShare() - getWithdrawn[_tokenId]; 
}

/// @notice Get the amount that can be withdrawn per share.
function _getWithdrawablePerShare() private view returns (uint256) {
    return (_totalWithdrawn + _asset.balanceOf(address(this))) / getTotalShares;
}
```

### Proof of Concept

Consider the following scenario:

```solidity
getShares[_tokenId] = 1e8
getWithdrawn[_tokenId] = 0
_totalWithdrawn = 0
_asset.balanceOf(address(this)) = 1e9 (1000 USDC)
getTotalShares = 5e8 + 1
```

The current calculation will yield:

```solidity
_getWithdrawablePerShare() = 1e9 / (5e8 + 1) = 1
_getAvailable() = 1e8 * 1 - 0 = 1e8 = 100000000
```

However, the users should actually receive:

```solidity
getShares[_tokenId] * _asset.balanceOf(address(this)) / getTotalShares
= 1e8 * 1e9 / (5e8 + 1) = 199999999
```

As shown, the users lose almost 50% of what they should receive.

### Recommended Mitigation Steps

Change the order of calculation to multiply before division.

### Assessed type

Math

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/67#event-12543163376)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Change order in multiplication/division as suggested.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/42), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/51) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/3).

***

## [[H-03] Function `distribute()` lacks access control allowing anyone to spam and disrupt the pool's accounting](https://github.com/code-423n4/2024-04-gondi-findings/issues/64)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/64), also found by [zhaojie](https://github.com/code-423n4/2024-04-gondi-findings/issues/7)*

The `LiquidationDistributor` contract manages the distribution of funds after a liquidation auction is settled. It distributes the received funds to the lenders of the loan. If the lender has implemented the `LoanManager` interface, it will also call `loanLiquidation()` on the lender's address. The Pool, when `loanLiquidation()` is called, will conduct an accounting process to ensure that the received funds are fairly distributed to the depositors.

```solidity
function loanLiquidation(
    uint256 _loanId,
    uint256 _principalAmount,
    uint256 _apr,
    uint256,
    uint256 _protocolFee,
    uint256 _received,
    uint256 _startTime
) external override onlyAcceptedCallers {
    uint256 netApr = _netApr(_apr, _protocolFee);
    uint256 interestEarned = _principalAmount.getInterest(netApr, block.timestamp - _startTime);
    uint256 fees = IFeeManager(getFeeManager).processFees(_received, 0);
    getCollectedFees += fees;
    // @audit Accounting logic
    _loanTermination(msg.sender, _loanId, _principalAmount, netApr, interestEarned, _received - fees);
}
```

However, the `distribute()` function lacks access control. Consequently, an attacker could directly call it with malicious data, leading to incorrect accounting in the Pool.

### Proof of Concept

Observe how the `loanLiquidation()` function is called:

```solidity
function _handleLoanManagerCall(IMultiSourceLoan.Tranche calldata _tranche, uint256 _sent) private {
    if (getLoanManagerRegistry.isLoanManager(_tranche.lender)) {
        LoanManager(_tranche.lender).loanLiquidation(
            _tranche.loanId,
            _tranche.principalAmount,
            _tranche.aprBps,
            _tranche.accruedInterest,
            0,
            _sent,
            _tranche.startTime
        );
    }
}
```

As shown above, the `principalAddress` is not passed in, meaning it will not be validated by the Pool. Therefore, an attacker can simply call the `distribute()` function with `loan.principalAddress` set to a random ERC20 token. This token will still be transferred to the Pool. However, the Pool will mistake this token as its asset token (USDC/WETH) and perform the accounting accordingly.

### Recommended Mitigation Steps

Only allow Loan contracts to call the `distribute()` function.

### Assessed type

Access Control

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/64#event-12543191121)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added caller check to avoid anyone calling `distribute`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/43), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/52) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/4).

***

## [[H-04] Function `refinanceFromLoanExecutionData()` does not check `executionData.tokenId == loan.nftCollateralTokenId`](https://github.com/code-423n4/2024-04-gondi-findings/issues/54)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/54), also found by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/78) and [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/14)*

The `refinanceFromLoanExecutionData()` function is used to refinance a loan from `LoanExecutionData`. It allows borrowers to use outstanding offers for new loans to refinance their current loan. This function essentially combines two actions: it processes the repayment for the previous loan and then emits a new loan.

The key difference is that the same NFT is used as collateral for the new loan, so it does not need to be transferred out of the protocol and then transferred back in. However, there is no check to ensure that the NFT id of the old loan matches the NFT id of the new execution data.

Therefore, the new loan may have a collateral NFT that does not match the NFT that the lender requested in their offers.

```solidity
/// @dev We first process the incoming offers so borrower gets the capital. After that, we process repayments.
///      NFT doesn't need to be transferred (it was already in escrow)
(uint256 newLoanId, uint256[] memory offerIds, Loan memory loan, uint256 totalFee) =
_processOffersFromExecutionData(
    borrower,
    executionData.principalReceiver,
    principalAddress,
    nftCollateralAddress,
    executionData.tokenId, // @audit No check if matched with loan.nftCollateralTokenId
    executionData.duration,
    offerExecution
);
```

### Proof of Concept

As we can see, `executionData.tokenId` is passed to the `_processOffersFromExecutionData()` function instead of `loan.nftCollateralTokenId`. This function performs all the checks to ensure that the lenders' offers accept this NFT.

```solidity
function _processOffersFromExecutionData(
    address _borrower,
    address _principalReceiver,
    address _principalAddress,
    address _nftCollateralAddress,
    uint256 _tokenId,
    uint256 _duration,
    OfferExecution[] calldata _offerExecution
) private returns (uint256, uint256[] memory, Loan memory, uint256) {
  ...
  _validateOfferExecution(
      thisOfferExecution,
      _tokenId,
      offer.lender,
      offer.lender,
      thisOfferExecution.lenderOfferSignature,
      protocolFee.fraction,
      totalAmount
  );
  ...
}
```

Eventually, it calls the `_checkValidators()` function to check the NFT token ID.

```solidity
function _checkValidators(LoanOffer calldata _loanOffer, uint256 _tokenId) private {
    uint256 offerTokenId = _loanOffer.nftCollateralTokenId;
    if (_loanOffer.nftCollateralTokenId != 0) {
        if (offerTokenId != _tokenId) {
            revert InvalidCollateralIdError();
        }
    } else {
        uint256 totalValidators = _loanOffer.validators.length;
        if (totalValidators == 0 && _tokenId != 0) {
            revert InvalidCollateralIdError();
        } else if ((totalValidators == 1) && (_loanOffer.validators[0].validator == address(0))) {
            return;
        }
        for (uint256 i = 0; i < totalValidators;) {
            IBaseLoan.OfferValidator memory thisValidator = _loanOffer.validators[i];
            IOfferValidator(thisValidator.validator).validateOffer(_loanOffer, _tokenId, thisValidator.arguments);
            unchecked {
                ++i;
            }
        }
    }
}
```

However, since `executionData.tokenId` is passed in, an attacker could pass in a valid `tokenId` (an NFT id that will be accepted by all lender offers). But in reality, the `loan.nftCollateralTokenId` will be the NFT kept in escrow.

### Recommended Mitigation Steps

Add a check to ensure that `executionData.tokenId` is equal to `loan.nftCollateralTokenId`.

### Assessed type

Invalid Validation

**[0xend (Gondi) confirmed via duplicate Issue #14](https://github.com/code-423n4/2024-04-gondi-findings/issues/14#event-12543529247)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added `tokenIdCheck`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/44), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/53) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/5).

***

## [[H-05] `triggerFee` is stolen from other auctions during `settleWithBuyout()`](https://github.com/code-423n4/2024-04-gondi-findings/issues/50)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/50), also found by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/30)*

The function `settleWithBuyout()` is used to settle an auction with a buyout from the main lender. This lender needs to repay all other lenders and will receive the NFT collateral. Near the end of the function, the `triggerFee` is also paid to the auction originator. However, the funds used to pay this fee are taken directly from the contract balance, even though the main lender doesn't transfer these funds into the contract.

```solidity
function settleWithBuyout(
    ...
) external nonReentrant {
    ...
    // @note Repay other lenders
    ERC20 asset = ERC20(_auction.asset); 
    uint256 totalOwed;
    for (uint256 i; i < _loan.tranche.length;) {
        ...
    }
    IMultiSourceLoan(_auction.loanAddress).loanLiquidated(_auction.loanId, _loan);
    
    // @audit There is no fund in this contract to pay triggerFee
    asset.safeTransfer(_auction.originator, totalOwed.mulDivDown(_auction.triggerFee, _BPS)); 
    ...
}
```

As a result, if the auction contract balance is insufficient to cover the fee, the function will simply revert and prevent the main lender from buying out. In other cases where multiple auctions are running in parallel, the `triggerFee` will be deducted from the other auctions. This could lead to the last auctions being unable to settle due to insufficient balance.

### Proof of Concept

The function `settleWithBuyout()` is called before any `placeBid()` so the funds is only from main lender. In the `settleWithBuyout()`, there are 2 transfers asset. One is to pay other lenders and one is to pay the `triggerFee`. As you can see in the code snippet, there is no `triggerFee` transfer from sender to originator.

### Recommended Mitigation Steps

Consider using `safeTransferFrom()` to pay the `triggerFee` from the sender's address, rather than using `safeTransfer()` to pay the `triggerFee` from the contract balance.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/50#event-12543486840)**

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/50#issuecomment-2067722171):**
 > Sustaining high severity because this is going to cause a loss of principal to other auctions.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Change to `safeTransferFrom` buyer.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/45), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/54) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/6).

***

## [[H-06] Function `settleWithBuyout()` does not call `LoanManager.loanLiquidation()` during a buyout](https://github.com/code-423n4/2024-04-gondi-findings/issues/49)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/49), also found by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/9)*

Lenders in the Gondi protocol could be EOA and Gondi Pool. Gondi Pool, an ERC4626, allows anyone to deposit funds and earn yield from lending on Gondi. Gondi Pool implemented the `LoanManager` interfaces, which include the `validateOffer()`, `loanRepayment()`, and `loanLiquidation()` functions. The functions `loanRepayment()` and `loanLiquidation()` are called when a borrower repays the loan or the loan is liquidated, i.e., when the Pool receives funds back from `MultiSourceLoan`. Both functions is used to update the queue accounting and the outstanding values of the Pool.

```solidity
ERC20 asset = ERC20(_auction.asset); 
uint256 totalOwed;
// @audit Repay lender but not call LoanManager.loanLiquidation()
for (uint256 i; i < _loan.tranche.length;) {
    if (i != largestTrancheIdx) { 
        IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
        uint256 owed = thisTranche.principalAmount + thisTranche.accruedInterest
            + thisTranche.principalAmount.getInterest(thisTranche.aprBps, block.timestamp - thisTranche.startTime);
        totalOwed += owed; 
        asset.safeTransferFrom(msg.sender, thisTranche.lender, owed);
    }
    unchecked {
        ++i;
    }
}
IMultiSourceLoan(_auction.loanAddress).loanLiquidated(_auction.loanId, _loan);
```

In the `settleWithBuyout()` function, the main lender buys out the loan by repaying all other lenders directly. However, `loanLiquidation()` is not called, leading to incorrect accounting in the Pool.

### Proof of Concept

The `loanLiquidation()` function handles accounting in the pool.

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L449-L463>

```solidity
function loanLiquidation(
    ...
) external override onlyAcceptedCallers {
    uint256 netApr = _netApr(_apr, _protocolFee);
    uint256 interestEarned = _principalAmount.getInterest(netApr, block.timestamp - _startTime);
    uint256 fees = IFeeManager(getFeeManager).processFees(_received, 0);
    getCollectedFees += fees;
    _loanTermination(msg.sender, _loanId, _principalAmount, netApr, interestEarned, _received - fees);
}
```

### Recommended Mitigation Steps

Consider checking and calling `loanLiquidation()` in `settleWithBuyout()` to ensure accurate accounting in the pool.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/49#issuecomment-2067756607):**
 > Changing interest paid to use the end of the loan (this appears in another issue since this delta in time otherwise breaks the `maxSeniorRepayment` concept).

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added `loanLiquidation` call.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/46), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/55) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/7).

***

## [[H-07] `deployWithdrawalQueue()` need to clear `_queueAccounting[lastQueueIndex]`](https://github.com/code-423n4/2024-04-gondi-findings/issues/48)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/48)*

In `deployWithdrawalQueue()`, only clears `_queueOutstandingValues[lastQueueIndex]` and `_outstandingValues`, but doesn't clear `_queueAccounting[lastQueueIndex]`.

```solidity
    function deployWithdrawalQueue() external nonReentrant {
...

        /// @dev We move outstanding values from the pool to the queue that was just deployed.
        _queueOutstandingValues[pendingQueueIndex] = _outstandingValues;
        /// @dev We clear values of the new pending queue.
        delete _queueOutstandingValues[lastQueueIndex];
        delete _outstandingValues;
@>      //@audit miss delete _queueAccounting[lastQueueIndex]

        _updateLoanLastIds();

@>      _pendingQueueIndex = lastQueueIndex;

        // Cannot underflow because the sum of all withdrawals is never larger than totalSupply.
        unchecked {
            totalSupply -= sharesPendingWithdrawal;
        }
    }

```

After this method, anyone calling `queueClaimAll()` will use this stale data `_queueAccounting[lastQueueIndex]`.

`queueClaimAll()` -> `_queueClaimAll(_pendingQueueIndex)`-> `_updatePendingWithdrawalWithQueue(_pendingQueueIndex)`

```solidity
    function _updatePendingWithdrawalWithQueue(
        uint256 _idx,
        uint256 _cachedPendingQueueIndex,
        uint256[] memory _pendingWithdrawal
    ) private returns (uint256[] memory) {
        uint256 totalReceived = getTotalReceived[_idx];
        uint256 totalQueues = getMaxTotalWithdrawalQueues + 1;
        /// @dev Nothing to be returned
        if (totalReceived == 0) {
            return _pendingWithdrawal;
        }
        getTotalReceived[_idx] = 0;

        /// @dev We go from idx to newer queues. Each getTotalReceived is the total
        /// returned from loans for that queue. All future queues/pool also have a piece of it.
        /// X_i: Total received for queue `i`
        /// X_1  = Received * shares_1 / totalShares_1
        /// X_2 = (Received - (X_1)) * shares_2 / totalShares_2 ...
        /// Remainder goes to the pool.
        for (uint256 i; i < totalQueues;) {
            uint256 secondIdx = (_idx + i) % totalQueues;
@>          QueueAccounting memory queueAccounting = _queueAccounting[secondIdx];
            if (queueAccounting.thisQueueFraction == 0) {
                unchecked {
                    ++i;
                }
                continue;
            }
            /// @dev We looped around.
@>          if (secondIdx == _cachedPendingQueueIndex + 1) {
                break;
            }
            uint256 pendingForQueue = totalReceived.mulDivDown(queueAccounting.thisQueueFraction, PRINCIPAL_PRECISION);
            totalReceived -= pendingForQueue;

            _pendingWithdrawal[secondIdx] = pendingForQueue;
            unchecked {
                ++i;
            }
        }
        return _pendingWithdrawal;
    }
```

### Impact

Not clearing `_queueAccounting[lastQueueIndex]` when executing `queueClaimAll()` will use this stale data to distribute `totalReceived`.

### Recommended Mitigation

```diff
    function deployWithdrawalQueue() external nonReentrant {
...

        /// @dev We move outstaning values from the pool to the queue that was just deployed.
        _queueOutstandingValues[pendingQueueIndex] = _outstandingValues;
        /// @dev We clear values of the new pending queue.
        delete _queueOutstandingValues[lastQueueIndex];
+       delete _queueAccounting[lastQueueIndex]
        delete _outstandingValues;


        _updateLoanLastIds();

        _pendingQueueIndex = lastQueueIndex;

        // Cannot underflow because the sum of all withdrawals is never larger than totalSupply.
        unchecked {
            totalSupply -= sharesPendingWithdrawal;
        }
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/48#event-12543494424)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Clear state vars.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/47), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/56) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/8).

***

## [[H-08] Incorrect circular array check in `_updatePendingWithdrawalWithQueue` flow, causing received funds to be added to the wrong queues](https://github.com/code-423n4/2024-04-gondi-findings/issues/47)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/47)*

In Pool.sol, `queueClaimAll` flow will transfer received funds (returned funds from loans) for each queue to newer queues.

Received funds for a given queue are intended to be [distributed to newer queues](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L656-L661):

>        /// @dev We go from idx to newer queues. Each getTotalReceived is the total        
>        /// returned from loans for that queue. All future queues/pool also have a piece of it.
>        /// X_i: Total received for queue `i`
>        /// X_1  = Received * shares_1 / totalShares_1
>        /// X_2 = (Received - (X_1)) * shares_2 / totalShares_2 ...
>        /// Remainder goes to the pool.

This logic is implemented in `_updatePendingWithdrawalWithQueue()`. Due to queue arrays are circular, the array index never exceeds `getMaxTotalWithdrawalQueues` and will restart from `0`.

`% totalQueues` should be used when checking array indexes in most cases. However, [in the queue index for-loop](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L672C17-L672C57), `if (secondIdx == _cachedPendingQueueIndex + 1) {break;}` is used to break the loop instead of `secondIdx == (_cachedPendingQueueIndex + 1)%totalQueues`.

This is problematic in some cases:

1. When `_cachedPendingQueueIndex` `<` `getMaxTotalWithdrawalQueues`.
`_updatePendingWithdrawalWithQueue()` will always skip the oldest queue when distributing `getTotalReceived[_idx]` funds.

    In `_queueClaimAll()`, [the first for-loop start with the oldestQueueIndex](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L693) (`_cachedPendingQueueIndex + 1) % totalQueues + 0)%totalQueues`). When (`_cachedPendingQueueIndex + 1`) `% totalQueues== _cachedPendingQueueIndex + 1`, this first iteration will always result in a break in the [second for-loop](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L662), where `secondIdx == oldestQueueIndex == _cachedPendingQueueIndex + 1`.

    As a result, any received funds from the `oldesQueueIndex` ([`getTotalReceived\[oldestQueueIndex\]`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L648)) will not be distributed and directly [deleted](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L654) (`getTotalReceived[_idx] = 0;`).

2. When `_cachedPendingQueueIndex` `==` `getMaxTotalWithdrawalQueues`
The [second for-loop](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L662) will never break, because `secondIdx < _cachedPendingQueueIndex + 1`. `for (uint256 i; i < totalQueues;)` will always run `getMaxTotalWithdrawalQueues+1` times. This will result in received funds from any queues being distributed to both newer queues and older queues.

### Recommended Mitigation Steps

Based on my understanding, this should be `if (i≠0 && secondIdx == (_cachedPendingQueueIndex + 1)%totalQueues) { break;}`

### Assessed type

Error

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/47#issuecomment-2063430859):**
 > > causing received funds to be added to the wrong queues
> 
> What are the consequences of that? I'll might consider high severity if this leads to frozen funds.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/47#issuecomment-2067281634):**
 > Conversation continued over discord. There's a bug here I believe (a high severity one), the condition for breaking the loop should be `secondIdx == _cachedPendingQueueIndex`.

**[0xA5DF (judge) increased severity to High](https://github.com/code-423n4/2024-04-gondi-findings/issues/47#issuecomment-2068017566)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Need to break 1 before.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/48), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/57) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/9).

***

## [[H-09] Incorrect accounting of `_pendingWithdrawal` in `queueClaiming` flow](https://github.com/code-423n4/2024-04-gondi-findings/issues/46)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/46), also found by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/19)*

Incorrect accounting of `_pendingWithdrawal` in `queueClaiming` flow, funds received from a previous queue index will be lost.

### Proof of Concept

In Pool.sol's `queueClaimAll()`, each queue's received funds `getTotalReceived[_idx]` (total returned funds from loans for that queue) will be distributed to all newer queues in a for-loop.

There are two for-loops in this flow. [First for-loop](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L692) iterate through each `pendingWithdrawal` index to get the received funds for that queue index (`getTotalReceived[_idx]`). [Second for-loop](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L662) iterates through each queue index again to distribute funds from `_idx`.

The problem is in the second for-loop, `_pendingWithdrawal[secondIdx]` will not accumulate distributed funds from previous queue indexes, instead it erases the value from previous loops and only records the last queue's received funds.

```solidity
//src/lib/pools/Pool.sol
    function _updatePendingWithdrawalWithQueue(
        uint256 _idx,
        uint256 _cachedPendingQueueIndex,
        uint256[] memory _pendingWithdrawal
    ) private returns (uint256[] memory) {
        uint256 totalReceived = getTotalReceived[_idx];
        uint256 totalQueues = getMaxTotalWithdrawalQueues + 1;
...
        getTotalReceived[_idx] = 0;
...
        for (uint256 i; i < totalQueues;) {
...
              //@audit this should be _pendingWithdraw[secondIdx] += pendingForQueue; Current implementation directly erases `pendingForQueue` value distributed from other queues. 
|>            _pendingWithdrawal[secondIdx] = pendingForQueue;
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L678>

Note that `getTotalReceived[_idx]` will be cleared before the for-loop (`getTotalReceived[_idx] = 0`), meaning that the erased `pendingForQueue` values from previous loops cannot be recovered. `_pendingWithdrawal` will be incorrect.

### Recommended Mitigation Steps

Change into `_pendingWithdrawal[secondIdx] + = pendingForQueue;`.

### Assessed type

Error

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/46#event-12543628520)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Missing `+`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/49), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/58) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/10).

***

## [[H-10] The attackers front-running `repayloans` so that the debt cannot be repaid](https://github.com/code-423n4/2024-04-gondi-findings/issues/35)
*Submitted by [zhaojie](https://github.com/code-423n4/2024-04-gondi-findings/issues/35), also found by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/57)*

The attackers make it impossible for borrowers to repay their debts, and the collateral is liquidated when the debts mature.

### Proof of Concept

`repayLoan` needs to check the `loanId`; if the id is inconsistent it will revert.

```solidity
    function repayLoan(LoanRepaymentData calldata _repaymentData) external override nonReentrant {
        uint256 loanId = _repaymentData.data.loanId;
        Loan calldata loan = _repaymentData.loan;
        .....
@>      _baseLoanChecks(loanId, loan);
        .....
    }
    
    function _baseLoanChecks(uint256 _loanId, Loan memory _loan) private view {
        if (_loan.hash() != _loans[_loanId]) {
            revert InvalidLoanError(_loanId);
        }
        if (_loan.startTime + _loan.duration < block.timestamp) {
            revert LoanExpiredError();
        }
    }
```

The problem is that `_loans[_loanId]` can change; for example, when `mergeTranches` deletes the old `loanId` and writes the new one:

```solidity
    _loans[loanId] = loanMergedTranches.hash();
    delete _loans[_loanId];
```

An attacker can use the `front-running` attack method. When `repayLoan` is called, execute the `mergeTranches` function in advance, and make the id in `_loans` updated. In this case, the `repayLoan` execution will fail due to inconsistent `_loanId`.

If the attacker keeps using this attack, the borrower's debt will not be repaid; eventually causing the collateral to be liquidated.

In addition to the `mergeTranches` function, the attacker can also call `addNewTranche`, and the borrower can also call the refinance-related function, again causing `_loanId` to be updated.

An attacker can also use the same method to attack `refinance` related functions, making refinance unable to execute. An attacker can also use the same method to attack the `liquidateLoan` function, making it impossible for debts to be cleared.

### Tools Used

VScode

### Recommended Mitigation Steps

Do not delete `_loanId`.

### Assessed type

DoS

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2061734850):**
 > I have some doubts about severity, since this requires too many resources from the attacker (see [here](https://github.com/code-423n4/org/issues/143)), and the `addNewTranche()` requires the lender's signature (and when using `mergeTranches()` alone the attacker would eventually run out of tranches to merge).

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2067349645):**
 > I think this is low (agree with judge for those reasons).

**[0xA5DF (judge) decreased severity to Low and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2067728846):**
 > I think there are too many limitations on this one, and the motivation for the attacker isn't very high - they're not going to get the entire principal from this.

**[0xend (Gondi) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2067773961):**
 > Given the limit on tranches the attacker can only run this a handful of times.

**[zhaojie (warden) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2069358048):**
 > I think it's a `high risk`, because anyone can be an attacker, so Lender can be an attacker.
>
> If the lender does not want the borrower to repay the debt, the lender can use `addNewTranche/mergeTranches` and to attack `repayLoans` and make the borrower's loan impossible to repay, especially when the loan is about to expire.
> This causes the borrower's NFT to be loss, so it would have a high impact.
> 
> When `_liquidateLoan`, if `_canClaim == true`, the borrower can get the NFT directly:
>
> ```solidity
>     function _liquidateLoan....{
>        ....
>         if (_canClaim) {
>             ERC721(_loan.nftCollateralAddress).transferFrom(
>                 address(this), _loan.tranche[0].lender, _loan.nftCollateralTokenId
>             );
>             emit LoanForeclosed(_loanId);
> 
>             liquidated = true;
>         } 
>     ....
>     }
> 
>      function liquidateLoan(uint256 _loanId, Loan calldata _loan)...  {
>        .....
>         (bool liquidated, bytes memory liquidation) = _liquidateLoan(
>             _loanId, _loan, _loan.tranche.length == 1 && !getLoanManagerRegistry.isLoanManager(_loan.tranche[0].lender)
>         );
>        ......
>      }
> ```
> 
> An attacker/lender can use `mergeTranches` to make `_loan.tranche.length == 1`. The key issue is that `loanId` will be reset.

**[0xA5DF (judge) increased severity to High and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2069536102):**
 > You're right that the lender has a high motivation to execute this attack. You're also right that when the borrower attempts to repay close to the expiry time this attack becomes feasible.
 >
> While some conditions are required in order for this to work, it still seems pretty likely to happen. Due to those reasons I'm reinstating high severity.
> 
> Side note: I think that a better mitigation would be to not allow functions that change the `loanID` to run near the expiry time.

**[0xend (Gondi) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/35#issuecomment-2098898343):**
 > No specific PR here since it's addressed when limiting `addNewTranche` to only be able to be called by the borrower and checking in `refinancePartial` that there's at least one tranche being refinanced. This ends up limiting the number of times a loan can be locked by the lender (tranches are locked for some time after a refinance for future ones).

***

## [[H-11] Incorrect protocol fee implementation results in `outstandingValues` to be mis-accounted in Pool.sol](https://github.com/code-423n4/2024-04-gondi-findings/issues/33)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/33)*

The vulnerability is that `LiquidationDistributer::_handleLoanMangerCall` [hardcodes `0` as protocol fee](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/LiquidationDistributor.sol#L117) when calling `LoanManager(_tranche.lender).loanLiquidation()`.

```solidity
//src/lib/LiquidationDistributor.sol
    function _handleLoanManagerCall(IMultiSourceLoan.Tranche calldata _tranche, uint256 _sent) private {
        if (getLoanManagerRegistry.isLoanManager(_tranche.lender)) {
            LoanManager(_tranche.lender).loanLiquidation(
                _tranche.loanId,
                _tranche.principalAmount,
                _tranche.aprBps,
                _tranche.accruedInterest,
   |>           0,  //@audit this should be the actual protocol fee fraction
                _sent,
                _tranche.startTime
            );
        }
    }
```

`_handleLoanManagerCall()` will be called as part of the flow to [distribute proceeds](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L288) from a liquidation.

When protocol fee is hardcoded `0`, in the [`Pool::loanliquidation`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/LiquidationDistributor.sol#L112) call, [`netApr` will not account for protocol fee fraction](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L458) which will [inflate the `_apr` used to offset `_outstandingValues.sumApr`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L751), a state variable that accounts for the total annual apr of outstanding loans.

```solidity
//src/lib/pools/Pool.sol
        OutstandingValues memory __outstandingValues,
        uint256 _principalAmount,
        uint256 _apr,
        uint256 _interestEarned
    ) private view returns (OutstandingValues memory) {
...
         //@audit inflated _apr will offset __outstandingValues.sumApr to an incorrect lower value, causing accounting error
|>        __outstandingValues.sumApr -= uint128(_apr * _principalAmount);
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L751>

For comparison, when a loan is created ([`pool::validateOffer`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L760)), the actual protocol fee ([`protocolFee.fraction`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L1008)) will be passed, and `__outstandingValues.sumApr` will be added with the [post-fee apr value](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L509), instead of the before-fee apr.

State accounting `__outstandingValues` will be incorrect, all flows that consume `__outstandingValues.sumApr` when calculating interests will be affected.

### Recommended Mitigation Steps

User `_loan.protocolFee `instead of `0`.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/33#issuecomment-2067353471):**
 > Messes up with accounting, I think this is a high one.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Passing protocol fee.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/89), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/59) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/12).

***

## [[H-12] `addNewTranche()` no authorization from borrower](https://github.com/code-423n4/2024-04-gondi-findings/issues/29)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/29), also found by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/73), [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/52), and [zhaojie](https://github.com/code-423n4/2024-04-gondi-findings/issues/38)*

For `addNewTranche()`, the code implementation is as follows：

```solidity
    function addNewTranche(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan,
        bytes calldata _renegotiationOfferSignature
    ) external nonReentrant returns (uint256, Loan memory) {
        uint256 loanId = _renegotiationOffer.loanId;

        _baseLoanChecks(loanId, _loan);
        _baseRenegotiationChecks(_renegotiationOffer, _loan);
@>      _checkSignature(_renegotiationOffer.lender, _renegotiationOffer.hash(), _renegotiationOfferSignature);
        if (_loan.tranche.length == getMaxTranches) {
            revert TooManyTranchesError();
        }

        uint256 newLoanId = _getAndSetNewLoanId();
        Loan memory loanWithTranche = _addNewTranche(newLoanId, _loan, _renegotiationOffer);
        _loans[newLoanId] = loanWithTranche.hash();
        delete _loans[loanId];

        ERC20(_loan.principalAddress).safeTransferFrom(
            _renegotiationOffer.lender, _loan.borrower, _renegotiationOffer.principalAmount - _renegotiationOffer.fee
        );
        if (_renegotiationOffer.fee > 0) {
            /// @dev Cached
            ProtocolFee memory protocolFee = _protocolFee;
            ERC20(_loan.principalAddress).safeTransferFrom(
                _renegotiationOffer.lender,
                protocolFee.recipient,
                _renegotiationOffer.fee.mulDivUp(protocolFee.fraction, _PRECISION)
            );
        }

        emit LoanRefinanced(
            _renegotiationOffer.renegotiationId, loanId, newLoanId, loanWithTranche, _renegotiationOffer.fee
        );

        return (newLoanId, loanWithTranche);
    }
```

Currently only the signature of the `lender` is checked, not the authorization of the `borrower`. Then, any `lender` can add `tranche` to any `loan` by:

1. Specifying a very high apr.
2. Specifying any `_renegotiationOffer.fee`; for example: set `_renegotiationOffer.fee==_renegotiationOffer.principalAmount`.

This doesn't make sense for `borrower`. It is recommended that only the `borrower` performs this method.

### Impact

`lender` can be specified to generate a malicious `tranche` to compromise `borrower`.

### Recommended Mitigation

```diff
    function addNewTranche(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan,
        bytes calldata _renegotiationOfferSignature
    ) external nonReentrant returns (uint256, Loan memory) {
        uint256 loanId = _renegotiationOffer.loanId;
+       if (msg.sender != _loan.borrower) {
+           revert InvalidCallerError();
+       } 
        _baseLoanChecks(loanId, _loan);
        _baseRenegotiationChecks(_renegotiationOffer, _loan);
        _checkSignature(_renegotiationOffer.lender, _renegotiationOffer.hash(), _renegotiationOfferSignature);
        if (_loan.tranche.length == getMaxTranches) {
            revert TooManyTranchesError();
        }
```

### Assessed type

Context

**[0xend (Gondi) confirmed via duplicate Issue #52](https://github.com/code-423n4/2024-04-gondi-findings/issues/52#event-12543437001)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added caller check.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/90), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/60) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/13).

***

## [[H-13] `_processOffersFromExecutionData()` lack of check `executionData.duration<=offer.duration`](https://github.com/code-423n4/2024-04-gondi-findings/issues/28)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/28)*

`emitLoan()` only limits `offer.duration != 0`. There's no limit in `executionData.duration<=offer.duration`.

`emitLoan()` -> `_processOffersFromExecutionData()` -> `_validateOfferExecution()`

```solidity
    function _validateOfferExecution(
        OfferExecution calldata _offerExecution,
        uint256 _tokenId,
        address _lender,
        address _offerer,
        bytes calldata _lenderOfferSignature,
        uint256 _feeFraction,
        uint256 _totalAmount
    ) private {
...

@>      if (offer.duration == 0) {
            revert ZeroDurationError();
        }
        if (offer.aprBps == 0) {
            revert ZeroInterestError();
        }
        if ((offer.capacity > 0) && (_used[_offerer][offer.offerId] + _offerExecution.amount > offer.capacity)) { 
            revert MaxCapacityExceededError();
        }

        _checkValidators(_offerExecution.offer, _tokenId);
    }
```

If the `executionData.duration` time is not limited, it can lead to far exceeding the borrowing time `offer.duration`. If the `lender` is a `LoanManager`, when `repayLoan()` it can also exceed the maximum `pendingQueues`, leading to accounting issues.

### Impact

Far exceeding the borrowing time than `offer.duration`. If `lender` is `LoanManager` also exceeds max `pendingQueues`, causing bookkeeping issues.

### Recommended Mitigation

Check `executionData.duration<=offer[n].duration`.

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/28#event-12545511916)**

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/28#issuecomment-2067729769):**
> Sustaining high due to accounting issues.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added duration check.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/91), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/61) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/14).

***

## [[H-14] `mergeTranches()`/`refinancePartial()` lack of `nonReentrant`](https://github.com/code-423n4/2024-04-gondi-findings/issues/27)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/27)*

In `mergeTranches()`, the method's code implementation is as follows:

```solidity
 function mergeTranches(uint256 _loanId, Loan memory _loan, uint256 _minTranche, uint256 _maxTranche)
        external
        returns (uint256, Loan memory)
    {
        _baseLoanChecks(_loanId, _loan);
        uint256 loanId = _getAndSetNewLoanId();
        Loan memory loanMergedTranches = _mergeTranches(loanId, _loan, _minTranche, _maxTranche);
        _loans[loanId] = loanMergedTranches.hash();
        delete _loans[_loanId];

        emit TranchesMerged(loanMergedTranches, _minTranche, _maxTranche);

        return (loanId, loanMergedTranches);
    }
```

As shown above, this method lacks reentrancy protection, which could allow reentrancy attacks to manipulate the `_loans[]`.

Example: Suppose `_loans[1] = {NFT = 1}`
1. Alice calls `refinanceFromLoanExecutionData(_loans\[1],LoanExecutionData)`.
    - `LoanExecutionData.ExecutionData.OfferExecution.LoanOffer.OfferValidator\[0].validator` `=  CustomContract  => for callback`.
2. `refinanceFromLoanExecutionData()` -> `_processOffersFromExecutionData()` -> `_validateOfferExecution()` -> `_checkValidators()` -> `IOfferValidator(CustomContract).validateOffer()`.
3. In `IOfferValidator(CustomContract).validateOffer()`, call `MultiSourceLoan.mergeTranches(_loans[1])` -> pass without `nonReentrant`.
    - `_loans\[3] = newLoan.hash()`
4. Return to `refinanceFromLoanExecutionData()`, will execute:
    - `_loans\[2] = newOtherLoan.hash()`.

There will be `_loans[2]` and `_loans[3]`, both containing `NFT=1`.
Note: Both Loans 's lender are all himself:
1. The user can `repayLoan(_loans[2])` and get the NFT back.
2. Use the NFT to borrow other people's funds, e.g. to generate `_loans[100]`.
3. `repayLoan(_loans[3])`, get NFT back.

### Recommended Mitigation

Add `nonReentrant`:

```diff
 function mergeTranches(uint256 _loanId, Loan memory _loan, uint256 _minTranche, uint256 _maxTranche)
        external
+       nonReentrant
        returns (uint256, Loan memory)
    {
        _baseLoanChecks(_loanId, _loan);
        uint256 loanId = _getAndSetNewLoanId();

    function refinancePartial(RenegotiationOffer calldata _renegotiationOffer, Loan memory _loan)
        external
+       nonReentrant
        returns (uint256, Loan memory)
    {
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/27#event-12545516857)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added `nonReentrant`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/92), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/62) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/15).

***

## [[H-15] `_baseLoanChecks()` check errors for expire](https://github.com/code-423n4/2024-04-gondi-findings/issues/26)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/26), also found by [zhaojie](https://github.com/code-423n4/2024-04-gondi-findings/issues/36) and [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/85)*

`_baseLoanChecks()` is used to check whether Loan has expired:

```solidity
    function _baseLoanChecks(uint256 _loanId, Loan memory _loan) private view {
        if (_loan.hash() != _loans[_loanId]) {
            revert InvalidLoanError(_loanId);
        }
@>      if (_loan.startTime + _loan.duration < block.timestamp) {
            revert LoanExpiredError();
        }
    }
```

The expiration checks in liquidation are as follows:

```solidity
    function _liquidateLoan(uint256 _loanId, IMultiSourceLoan.Loan calldata _loan, bool _canClaim)
        internal
        returns (bool liquidated, bytes memory liquidation)
    {
...

        uint256 expirationTime = _loan.startTime + _loan.duration;
@>      if (expirationTime > block.timestamp) {
            revert LoanNotDueError(expirationTime);
        }
```

This way, both checks pass when `block.timestamp == _loan.startTime + _loan.duration`.

This leads to the problem that a malicious attacker can perform the following steps
when `block.timestamp == _loan.startTime + _loan.duration`:

1.  Alice calls `liquidateLoan` (`loandId` = 1) -> success.
    - `LoanLiquidator` generates an auction.
    - `_loans\[loandId = 1]` is still valid , and will only be cleared when the auction is over.
2.  Alice call `addNewTranche` (`loandId` = 1) -> success.
    - `_baseLoanChecks` (`loandId` = 1) will pass.
    - delete `_loans\[1]`;
    - `_loans\[2] = newLoan.hash()`.
3.  Bidding ends, call `loanLiquidated(loandId = 1)` will fail , because `_loans[1]` has been cleared.

### Impact

Maliciously disrupting the end of the bidding, causing the NFT/funds to be locked.

### Recommended Mitigation

```diff

    function _baseLoanChecks(uint256 _loanId, Loan memory _loan) private view {
        if (_loan.hash() != _loans[_loanId]) {
            revert InvalidLoanError(_loanId);
        }
-       if (_loan.startTime + _loan.duration < block.timestamp) {
+      if (_loan.startTime + _loan.duration <= block.timestamp) {
            revert LoanExpiredError();
        }
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/26#event-12545527904)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Strict `->` `<=`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/93), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/63) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/16).

***

## [[H-16] `validateOffer()` reentry to manipulate `exchangeRate`](https://github.com/code-423n4/2024-04-gondi-findings/issues/24)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/24)*

The current mechanism of `validateOffer()` is to first book `_outstandingValues` to increase, but `assets.balanceOf(address(this))` doesn't decrease immediately.

```solidity
    function validateOffer(bytes calldata _offer, uint256 _protocolFee) external override onlyAcceptedCallers {
..

        /// @dev Since the balance of the pool includes capital that is waiting to be claimed by the queues,
        ///      we need to check if the pool has enough capital to fund the loan.
        ///      If that's not the case, and the principal is larger than the currentBalance, then we need to reallocate
        ///      part of it.
        if (principalAmount > undeployedAssets) {
            revert InsufficientAssetsError();
        } else if (principalAmount > currentBalance) {
            IBaseInterestAllocator(getBaseInterestAllocator).reallocate(
                currentBalance, principalAmount - currentBalance, true
            );
        }
@>      /// @dev If the txn doesn't revert, we can assume the loan was executed.
@>      _outstandingValues = _getNewLoanAccounting(principalAmount, _netApr(apr, _protocolFee));
    }
```

I.e.: After this method is called, `_getUndeployedAssets()` is unchanged, but `_getTotalOutstandingValue()` is increased, so `totalAssets()` is increased, but `totalSupply` is unchanged, so `exchangeRate` is get bigger.

Originally, it was expected that after that, the Pool balance would be transferred at `MultiSourceLoan`, so `_getUndeployedAssets()` becomes smaller and `exchangeRate` returns to normal. But if it's possible to do callback malicious logic before `MultiSourceLoan` transfers away the Pool balance, it's possible to take advantage of this `exchangeRate` that becomes larger.

Example:
Suppose `_getUndeployedAssets()` = 1000, `_getTotalOutstandingValue()` = 1000 and `totalSupply` = 2000.

So:

`totalAssets() =  2000`
`exchangeRate = 1:1`

1. Alice calls `MultiSourceLoan.emitLoan()`.
    - `offer.lender = pool`.
    - `offer.principalAmount` = 500.
    - `offer.validators = CustomContract` -> for callback.
2. `emitLoan() -> Pool.validateOffer()`.
    - `_getUndeployedAssets()` = 1000 (no change).
    - `_getTotalOutstandingValue()` = 1000 + 500 = 1500 (more 500).
    - `totalAssets()` =  2500.
    - `exchangeRate` = 1.25 : 1.
3. `emitLoan()` -> `_checkValidators()` -> `CustomContract.validateOffer()`
    - In `CustomContract.validateOffer()` call `pool.redeem` (shares) use `exchangeRate = 1.25 : 1` to get more assets.
4. `emitLoan()` -> `asset.safeTransferFrom` (pool, receiver, 500).
    - `_getUndeployedAssets()` = 500.
    - `exchangeRate` Expect to return to normal.

### Impact

Manipulating the `exchangeRate` to redeem additional assets.

### Recommended Mitigation

In `validateOffer()`, restrict `offer.validators` to be an empty array to avoid callbacks.

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/24#event-12545610279)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> `validateOffer` changed to view so validators cannot change state.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/94), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/64) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/17).

***

## [[H-17] `refinanceFull`/`addNewTranche` reusing a lender's signature leads to unintended behavior](https://github.com/code-423n4/2024-04-gondi-findings/issues/13)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/13)*

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L358> 

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L194>

### Vulnerability details

In `MultiSourceLoan`, `refinanceFull()` and `addNewTranche()` use the same signature.

```solidity
    function refinanceFull(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan,
        bytes calldata _renegotiationOfferSignature
    ) external nonReentrant returns (uint256, Loan memory) {
...
        if (lenderInitiated) {
            if (_isLoanLocked(_loan.startTime, _loan.startTime + _loan.duration)) {
                revert LoanLockedError();
            }
            _checkStrictlyBetter(
                _renegotiationOffer.principalAmount,
                _loan.principalAmount,
                _renegotiationOffer.duration + block.timestamp,
                _loan.duration + _loan.startTime,
                _renegotiationOffer.aprBps,
                totalAnnualInterest / _loan.principalAmount,
                _renegotiationOffer.fee
            );
        } else if (msg.sender != _loan.borrower) {
            revert InvalidCallerError();
        } else {
            /// @notice Borrowers clears interest
@>          _checkSignature(_renegotiationOffer.lender, _renegotiationOffer.hash(), _renegotiationOfferSignature);
            netNewLender -= totalAccruedInterest;
            totalAccruedInterest = 0;
        }
```

```solidity
    function addNewTranche(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan,
        bytes calldata _renegotiationOfferSignature
    ) external nonReentrant returns (uint256, Loan memory) {
...
        uint256 loanId = _renegotiationOffer.loanId;

        _baseLoanChecks(loanId, _loan);
        _baseRenegotiationChecks(_renegotiationOffer, _loan);
@>      _checkSignature(_renegotiationOffer.lender, _renegotiationOffer.hash(), _renegotiationOfferSignature);
        if (_loan.tranche.length == getMaxTranches) {
            revert TooManyTranchesError();
        }
```

So when `lender` signs `RenegotiationOffer`, it is meant to replace `tranche`, i.e. execute `refinanceFull()`. But a malicious user can use this sign and front-run execute `addNewTranche()`. 

`addNewTranche()` doesn't limit the `RenegotiationOffer` too much. The newly generated `Loan` will be approximately twice the total amount borrowed, and the risk of borrowing against the `lender` will increase dramatically.

### Impact

Maliciously using the signature of `refinanceFull()` to execute `addNewTranche()` will result in approximately double the borrowed amount, and the risk of borrowing will increase dramatically.

### Recommended Mitigation

In `RenegotiationOffer`, add a type field to differentiate between signatures.

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/13#event-12543544476)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Check `trancheIndex` to differentiate between `refiFull`/`addNewTranche`.

**Status:** Unmitigated. Full details in reports from [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/65), [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/18) and [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/95), and also included in the [Mitigation Review](#mitigation-review) section below.

***
 
# Medium Risk Findings (20)
## [[M-01] Invalid `maxTranches` check can result in `maxTranche` cap to be exceeded](https://github.com/code-423n4/2024-04-gondi-findings/issues/80)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/80), also found by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/66) and [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/31)*

In `src/lib/loans/MultiSourceLoan.sol`, there's max cap for the number of tranches in a loan as defined as [`getMaxTranches`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L50-L51). This cap can be exceeded.

There are two main vulnerabilities:
1. `getMaxTranches` is not checked in some key flows where tranches can be added. These including [`emitLoan()`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L124), `refinancePartial()`(-> [`_addTrancheFromPartial()`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L289)), [`refinanceFromLoanExecutionData()`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L306).

2. Where `getMaxTranches` is checked, the check is invalid. Only `_loan.tranche.length == getMaxTranches` is checked. But combined with (1), when number of tranches exceeds `getMaxTranches` in other flows, this check is invalid.

```solidity
//src/lib/loans/MultiSourceLoan.sol
    function addNewTranche(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan,
        bytes calldata _renegotiationOfferSignature
    ) external nonReentrant returns (uint256, Loan memory) {
...
          //@audit change to _loan.tranch.length >= getMaxTranches
|>        if (_loan.tranche.length == getMaxTranches) {
            revert TooManyTranchesError();
        }
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L359>

### Recommended Mitigation Steps

Add missing checks on `getMaxTranches` for all flows that might add tranches. In `addNewTranche`, change into `_loan.tranch.length >= getMaxTranches`.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/80#event-12543082583)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Check total tranches + min amount per tranche.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/96), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/66) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/19).

***

## [[M-02] A malicious user can take on a loan using an existing borrower's collateral in `refinanceFromLoanExecutionData()`](https://github.com/code-423n4/2024-04-gondi-findings/issues/76)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/76)*

In `MultiSourceLoan.sol`, `refinanceFromLoanExecutionData()` doesn't check whether `_loan.borrower == _loanExecutionData.borrower`, which is open rooms for exploits.

BorrowerB (malicious) can sign a `_loanExecutionData` offer and initiate a `refinanceFromLoanExecutionData()` call with Borrower A's loan. Borrower B will use Borrower A's collateral for his loan.

There are (2) vulnerabilities here:
1. `_validateExecutionData` will not check whether `_loan.borrower == _executionData.borrower`. In addition, it will directly [bypass the check](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L792) on `executionData`'s borrower signature as long as `msg.sender!=_loan.borrower`.

2. `refinanceFromLoanExecutionData()` doesn't check whether the new loanExecutiondata (`_loanExecutionData`) has the [same nft tokenId](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L334)(`executionData.tokenId`) as the [existing loan](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L308)(`_loan.nftCollateralTokenId`).

As a result, if `_loanExecutionData.borrower` (Borrower B) initiates `refinanceFromLoanExecutionData()` call, the following would happen:
- `msg.sender != _loan.borrower` (Borrwer A), this bypass `_validateExecutionData`'s signature check. Also, it will not revert because no checks on [address _borrower](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L319)(`loan.borrower==_loanExecutionData.borrower;`.

- There is no check on `_loanExecutionData.tokenId`. As long as `_loan` and `_loanExecutionData` has [the same `principalAddress` and the same `nftCollateralAddress`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L322), `_processOffersFromExecutionData()` will succeed in [transferring principal loans to Borrower B](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L1025).

- As long as the `_loan.borrower` (Borrower A) has the funds for [repayment](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L946). (Note: Borrower A might have approved `MultiSourceLoan.sol` for asset transfer if they are ready for repayments.), the tx will succeed and Borrower A's collateral will continually be locked for Borrower B's new loan.

The above steps can also happen in a front-running scenario, where Borrower B sees that Borrower A approves `MultiSourceLoan.sol` for loan repayments and front-run Borrower A's repayment with a new loan.

### Recommended Mitigation Steps

In `_validateExecutionData`, consider adding checks to ensure `address _borrower` `== _executionData.borrower`.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/76#event-12543103939)**

*Note: For full discussion, see [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/76).*

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Checking signature from the existing borrower.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/97), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/67) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/20).

***

## [[M-03] Function `addNewTranche()` should use `protocolFee` from `Loan` struct](https://github.com/code-423n4/2024-04-gondi-findings/issues/65)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/65)*

The protocol fee value is recorded and stored in the Loan struct when a new loan is issued. However, when adding a new tranche, the function uses the current value of `protocolFee.fraction` instead of the value stored in the Loan struct. This could result in inconsistencies in fee collection, as the protocol fee value might be updated by the admin, while the value stored in the Loan struct remains unchanged.

```solidity
if (_renegotiationOffer.fee > 0) {
    /// @dev Cached
    ProtocolFee memory protocolFee = _protocolFee;
    ERC20(_loan.principalAddress).safeTransferFrom(
        _renegotiationOffer.lender,
        protocolFee.recipient,
        _renegotiationOffer.fee.mulDivUp(protocolFee.fraction, _PRECISION) // @audit Use protocolFee from Loan instead
    );
}
```

### Proof of Concept

The protocol fee value is stored in the Loan struct when a new loan is opened.

```solidity
function _processOffersFromExecutionData(
  ...
) ... {
  Loan memory loan = Loan(
      _borrower,
      _tokenId,
      _nftCollateralAddress,
      _principalAddress,
      totalAmount,
      block.timestamp,
      _duration,
      tranche,
      protocolFee.fraction
  );
}
```

### Recommended Mitigation Steps

Consider using `_loan.protocolFee` instead of `protocolFee.fraction` in the `addNewTranche()` function.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/65#event-12543174602)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> `addNewTranche` uses `protocolFee` from struct.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/98), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/68) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/21).

***

## [[M-04] Function `Pool.validateOffer()` does not work correctly in case `principalAmount > currentBalance`](https://github.com/code-423n4/2024-04-gondi-findings/issues/63)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/63), also found by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/42) and [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/21)*

In the Pool contract, undeployed funds could be deposited to Aave or Lido to earn base yield. When an offer of Pool is accepted from `MultiSourceLoan`, the function `validateOffer()` is called to validate the terms and also to pull the undeployed funds back in case the contract balance is insufficient.

```solidity
if (principalAmount > undeployedAssets) {
    revert InsufficientAssetsError();
} else if (principalAmount > currentBalance) {
    IBaseInterestAllocator(getBaseInterestAllocator).reallocate(
        currentBalance, principalAmount - currentBalance, true // @audit Incorrect
    );
}
```

However, the input params of `reallocate()` are incorrect, resulting in the contract balance might still be insufficient for the loan after calling the function.

### Proof of Concept

Consider the scenario:

1. Assume we have `currentBalance = 500`, `baseRateBalance = 1000 usdc` and `principalAmount = 700 usdc`.
2. Since the current contract balance is insufficient (500 `<` 700), `reallocate()` will be called with input:

```solidity
reallocate(currentBalance, principalAmount - currentBalance, true)
reallocate(500, 200, true)
```

3. In function `reallocate()` shown in the code snippet below, we can see that in case `_currentIdle > _targetIdle`, the contract even deposits more funds to `AavePool` instead of withdrawing.

```solidity
function reallocate(uint256 _currentIdle, uint256 _targetIdle, bool) external {
    address pool = _onlyPool();
    if (_currentIdle > _targetIdle) {
        uint256 delta = _currentIdle - _targetIdle;
        ERC20(_usdc).transferFrom(pool, address(this), delta);
        IAaveLendingPool(_aavePool).deposit(_usdc, delta, address(this), 0);
    } else {
        uint256 delta = _targetIdle - _currentIdle;
        IAaveLendingPool(_aavePool).withdraw(_usdc, delta, address(this));
        ERC20(_usdc).transfer(pool, delta);
    }

    emit Reallocated(_currentIdle, _targetIdle);
}
```

### Recommended Mitigation Steps

Call `reallocate(0, principalAmount - currentBalance, true)` instead.

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/63#issuecomment-2060875577):**
 > If I understand correctly, the impact is DoS that occurs only under certain conditions; in that case, I think severity should be Medium.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/63#issuecomment-2067064553):**
 > Agree on the issue. I think it's Medium, not High.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Changed to reallocate (`currentBalance`, `principalAmount`, t`r`ue) instead of proposed solution (same result) to be compliant with the interface.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/99), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/69) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/22).

***

## [[M-05] Collected fees are never transferred out of Pool contract](https://github.com/code-423n4/2024-04-gondi-findings/issues/60)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/60), also found by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/84) and [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/18)*

Lenders in the Gondi protocol could be EOA or Gondi Pool. The Gondi Pool, an ERC4626, allows anyone to deposit funds and earn yield from lending on Gondi. When a loan is repaid or liquidated, the pool deducts a fee from the received amount before adding the rest to the pool balance. As shown in the `loanRepayment()` function, the fees are calculated by calling `processFees()` and then added to `getCollectedFees`. After that, the accounting function `_loanTermination()` is called with the amount being `received - fees`.

However, this fee is credited to `getCollectedFees` but never transferred out of the pool. As a result, these funds remain locked in the contract indefinitely.

```solidity
function loanRepayment(
    uint256 _loanId,
    uint256 _principalAmount,
    uint256 _apr,
    uint256,
    uint256 _protocolFee,
    uint256 _startTime
) external override onlyAcceptedCallers {
    uint256 netApr = _netApr(_apr, _protocolFee);
    uint256 interestEarned = _principalAmount.getInterest(netApr, block.timestamp - _startTime);
    uint256 received = _principalAmount + interestEarned;
    uint256 fees = IFeeManager(getFeeManager).processFees(_principalAmount, interestEarned);
    getCollectedFees += fees; // @audit getCollectedFees is never transfer out
    _loanTermination(msg.sender, _loanId, _principalAmount, netApr, interestEarned, received - fees);
}
```

### Proof of Concept

The `processFees()` function only calculates the fee but doesn't transfer anything.

```solidity
function processFees(uint256 _principal, uint256 _interest) external view returns (uint256) {
    /// @dev cached
    Fees memory __fees = _fees;
    return _principal.mulDivDown(__fees.managementFee, PRECISION)
        + _interest.mulDivDown(__fees.performanceFee, PRECISION);
}
```

Then after `getCollectedFees` is credited for `fees`, we can see this `getCollectedFees` is never transferred out of the pool.

### Recommended Mitigation Steps

Add a function to collect the credited fees `getCollectedFees` from the pool in the `FeeManager` contract.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/60#issuecomment-2067072726):**
 > Not sure if it's High; tend to think as high as those that would compromise user's assets. Definitely an issue though.

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/60#issuecomment-2067666515):**
 > Marking as med as fees falls under the definition 'leak of value'.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added `collectFees` method.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/100), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/70) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/23).

***

## [[M-06] Anyone can remove existing term without queueing through `setTerms()`](https://github.com/code-423n4/2024-04-gondi-findings/issues/59)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/59)*

In `PoolOfferHandler`, new terms require a two-step process for setting (`setTerms()` and `confirmTerms()`). The `setTerm()` function is `onlyOwner`, but the `confirmTerms()` function can be called by anyone. This function uses the provided input `__terms` from the caller to execute the logic. This could enable an attacker to remove all existing terms, even if the owner does not intend to do so (without pending through the `setTerms()` function).

```solidity
function confirmTerms(TermsKey[] calldata _termKeys, Terms[] calldata __terms) external { 
    if (block.timestamp - pendingTermsSetTime < NEW_TERMS_WAITING_TIME) {
        revert TooSoonError();
    }
    for (uint256 i = 0; i < __terms.length; i++) {
        if (_termKeys[i].duration > getMaxDuration) {
            revert InvalidDurationError();
        }
        uint256 pendingAprPremium = _pendingTerms[_termKeys[i].collection][_termKeys[i].duration][_termKeys[i]
            .maxSeniorRepayment][__terms[i].principalAmount];
        // @audit Can be used to remove terms without pending through setTerm()
        if (pendingAprPremium != __terms[i].aprPremium) {
            revert InvalidTermsError();
        }
        _terms[_termKeys[i].collection][_termKeys[i].duration][_termKeys[i].maxSeniorRepayment][__terms[i]
            .principalAmount] = __terms[i].aprPremium;
        delete _pendingTerms[_termKeys[i].collection][_termKeys[i].duration][_termKeys[i]
            .maxSeniorRepayment][__terms[i].principalAmount];
    }
    pendingTermsSetTime = type(uint256).max;

    emit TermsSet(_termKeys, __terms);
}
```

### Proof of Concept

Consider the following scenario:

1. The pool has 5 existing terms. Now the owner wants to create a new term in the Pool, so they call `setTerms()` with the `__terms` they want to set up. The new term is pending confirmation after a waiting period.
2. After `NEW_TERMS_WAITING_TIME`, an attacker calls `confirmTerms()` with `_termKeys` set to all 5 existing terms and `__terms.aprPremium = 0`.
3. The function executes with the input provided by the attacker. Since the `pendingAprPremium` of these terms is reset to `0` after it is confirmed earlier, the check `if (pendingAprPremium != __terms[i].aprPremium)` is bypassed. The attacker could set the `_terms[][][][]` mapping of existing loans to `0`.

### Recommended Mitigation Steps

Only allow the owner to call `confirmTerms()`.

### Assessed type

Invalid Validation

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/59#event-12543278732)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Terms must be passed in the confirm as well.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/101), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/71) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/24).

***

## [[M-07] Attacker can front-run and pass in empty terms, making it impossible to `confirmTerms()`](https://github.com/code-423n4/2024-04-gondi-findings/issues/58)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/58), also found by [zhaojie](https://github.com/code-423n4/2024-04-gondi-findings/issues/40) and [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/11)*

In `PoolOfferHandler`, setting new terms requires two steps (`setTerms()` and `confirmTerms()`). The `setTerm()` function is `onlyOwner`, but anyone can call the `confirmTerms()` function. At the end of the `confirmTerms()` function, `pendingTermsSetTime` is set to `type(uint256).max`, preventing the function from being called again.

Since `confirmTerms()` uses the caller's input to execute the setup, an attacker could input empty `__terms` to prevent the owner from setting up new terms.

### Proof of Concept

```solidity
// @audit Anyone can front-run and pass in empty terms, making it impossible to confirmTerms
function confirmTerms(TermsKey[] calldata _termKeys, Terms[] calldata __terms) external { 
    if (block.timestamp - pendingTermsSetTime < NEW_TERMS_WAITING_TIME) {
        revert TooSoonError();
    }
    for (uint256 i = 0; i < __terms.length; i++) {
        if (_termKeys[i].duration > getMaxDuration) {
            revert InvalidDurationError();
        }
        uint256 pendingAprPremium = _pendingTerms[_termKeys[i].collection][_termKeys[i].duration][_termKeys[i]
            .maxSeniorRepayment][__terms[i].principalAmount];
        if (pendingAprPremium != __terms[i].aprPremium) {
            revert InvalidTermsError();
        }
        _terms[_termKeys[i].collection][_termKeys[i].duration][_termKeys[i].maxSeniorRepayment][__terms[i]
            .principalAmount] = __terms[i].aprPremium;
        delete _pendingTerms[_termKeys[i].collection][_termKeys[i].duration][_termKeys[i]
            .maxSeniorRepayment][__terms[i].principalAmount];
    }
    pendingTermsSetTime = type(uint256).max;

    emit TermsSet(_termKeys, __terms);
}
```

In this function, it loops through the input `__terms.length` list. If an attacker calls `confirmTerms()` with an empty `__terms` list, there will be no terms set, and `pendingTermsSetTime` is still set to `type(uint256).max`.

As a result, the owner will never be able to set up new terms for the pool because the attacker keeps spamming `confirmTerms()` when the `NEW_TERMS_WAITING_TIME` passes after the owner calls `setTerms()`.

### Recommended Mitigation Steps

Record the `__terms` list in the `setTerms()` function to confirm terms instead of using input from caller.

### Assessed type

DoS

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/58#event-12545396903)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Terms must be passed in the confirm as well.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/102), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/72) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/25).

***

## [[M-08] Borrower signature could be reused in `emitLoan()`](https://github.com/code-423n4/2024-04-gondi-findings/issues/51)
*Submitted by [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/51)*

The function `emitLoan()` is used to issue a new loan. This function could be called directly by the borrower or by a random address if the borrower has signed the `LoanExecutionData`.

```solidity
function emitLoan(LoanExecutionData calldata _loanExecutionData)
    external
    nonReentrant
    returns (uint256, Loan memory)
{
    address borrower = _loanExecutionData.borrower;
    ExecutionData calldata executionData = _loanExecutionData.executionData;
    (address principalAddress, address nftCollateralAddress) = _getAddressesFromExecutionData(executionData);

    OfferExecution[] calldata offerExecution = executionData.offerExecution;

    // @audit Check borrower signature or borrower is caller
    _validateExecutionData(_loanExecutionData, borrower); 
    ...
}

function _validateExecutionData(LoanExecutionData calldata _executionData, address _borrower) private view {
    if (msg.sender != _borrower) {
        _checkSignature(
            _executionData.borrower, _executionData.executionData.hash(), _executionData.borrowerOfferSignature
        );
    }
    if (block.timestamp > _executionData.executionData.expirationTime) {
        revert ExpiredOfferError(_executionData.executionData.expirationTime);
    }
}
```

However, there isn't a check to ensure the signature for the same `LoanExecutionData` can't be used to execute `emitLoan()` more than once. As a result, if the borrower repays the loan, an attacker could call `emitLoan()` again to initiate a new loan.

### Proof of Concept

Consider this scenario:

1. Lender Alice has an offer with a capacity of 50 ETH.
2. Borrower Bob signs a signature to take a 10 ETH loan with his NFT.
3. After Bob repays the loan, anyone can call `emitLoan()` using the previous signature to force Bob to take the 10 ETH loan again. Since the capacity of Alice's offer is 50 ETH, the signature can be reused up to 5 times.

### Recommended Mitigation Steps

Add a nonce to ensure a signature cannot be reused.

**[0xend (Gondi) acknowledged and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/51#issuecomment-2067101203):**
 > This could be the case but don't think is high given the struct has an expiration time to contemplate this. Borrower can avoid any issue by setting this to be close to the execution. Loans lasts for months, this will be at most a few hours.
 >
> To avoid an extra write+read, I'd probably make it very clear to the consumer of the smart contract.

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/51#issuecomment-2067672355):**
 > Marking as Medium due to sponsor comment. This requires some external conditions which don't seem to be easily satisfied.

**[0xend (Gondi) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/51#issuecomment-2067751372):**
> For the replay to happens:
> - Borrower needs to set an expiration longer than the intended time in which they'll repay the loan.
> - All lender offers must not expire before the loan is repaid AND have capacity.
> 
> Borrower has no reason to set this variable longer than `block.timestamp + small delta` (the time it remains in the mempool).

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Borrower should always set `block.timestamp` + small time delta as expiration to control when the loan can be started.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/103) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/26).

***

## [[M-09] Inconsistent accounting of `undeployedAssets` might result in undesired optimal range in the pool](https://github.com/code-423n4/2024-04-gondi-findings/issues/44)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/44), also found by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/32)*

`undeployedAssets` is calculated inconsistently. Currently in `_getUndeployedAssets()` the protocol collected fees are subtracted; however, in `validateOffer`, the protocol collected fees are not subtracted.

1. `_getUndeployedAssets()`: This is called in `deployWithdrawalQueue()` to [calculate proRata liquid assets](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L339) to the `queue.contractAddress`.

```solidity
    function _getUndeployedAssets() private view returns (uint256) {
        return asset.balanceOf(address(this)) + IBaseInterestAllocator(getBaseInterestAllocator).getAssetsAllocated()
|>            - getAvailableToWithdraw - getCollectedFees;
    }
```

2. `uint256 undeployedAssets`: This is manually calculated in `validateOffer` flow, which is used check whether the pool has [enough undeployed Assets to cover `loan.principalAmount`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L407).

```solidity
    function validateOffer(bytes calldata _offer, uint256 _protocolFee) external override onlyAcceptedCallers {
...
        uint256 currentBalance = asset.balanceOf(address(this)) - getAvailableToWithdraw;
        uint256 baseRateBalance = IBaseInterestAllocator(getBaseInterestAllocator).getAssetsAllocated();
         //@audit getCollectedFees is not subtracted
|>        uint256 undeployedAssets = currentBalance + baseRateBalance;
        (uint256 principalAmount, uint256 apr) = IPoolOfferHandler(getUnderwriter).validateOffer(
            IBaseInterestAllocator(getBaseInterestAllocator).getBaseAprWithUpdate(), _offer
        );
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L398>

Note that in (2), `undeployedAssets` are inflated because `getCollectedFees` are fees protocol collected from liquidation/repayment flows and shouldn't be considered as liquid assets to cover the loan principal amount.

3. `_reallocate()`: This also manually calculate total `undeployedAssets` amount, but again didn't account for `getCollectedFees`. `_reaalocate()` balances optimal target idle assets ratio by checking `currentBalance`/`total` ratio. Here, `currentBalance` should be additionally subtracted by `getCollectedFees` because fees are set aside and shouldn't be considered idle. This affects [optimal range check](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L581).

```solidity
    function _reallocate() private returns (uint256, uint256) {
        /// @dev Balance that is idle and belongs to the pool (not waiting to be claimed)
        uint256 currentBalance = asset.balanceOf(address(this)) - getAvailableToWithdraw;
        if (currentBalance == 0) {
            revert AllocationAlreadyOptimalError();
        }
        uint256 baseRateBalance = IBaseInterestAllocator(getBaseInterestAllocator).getAssetsAllocated();
        uint256 total = currentBalance + baseRateBalance;
        uint256 fraction = currentBalance.mulDivDown(PRINCIPAL_PRECISION, total);
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L572>

Inconsistent accounting in various flows may result in incorrect checks or undesirable optimal ranges.

### Recommended Mitigation Steps

Account for `getCollectedFees` in (2) and (3), noted above.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/44#event-12543633373)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Missing collected fees in accounting.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/104) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/74).

***

## [[M-10] Any liquidators can pretend to be a loan contract to validate offers, due to insufficient validation](https://github.com/code-423n4/2024-04-gondi-findings/issues/41)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/41)*

Accepted callers in a loan manager (e.g. `Pool.sol`) can be [either liquidators or loan contracts](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L73).

And only loan contracts should validate offers during a loan creation. However, the current access control check is insufficient in [`pool::validateOffer`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L392), which allows liquidators to pretend to be a loan contract, and [directly modify storage (`__outstandingValues`)](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L414-L415) bypassing additional checks and accounting in a loan contract.

```solidity
//src/lib/pools/Pool.sol
    //@audit onlyAcceptedCallers only doesn't ensure caller is a loan contract
|>    function validateOffer(bytes calldata _offer, uint256 _protocolFee) external override onlyAcceptedCallers {
        if (!isActive) {
            revert PoolStatusError();
        }
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L392>

Current access control check ([`onlyAcceptedCallers`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L58)) only ensures caller is accepted caller but doesn't verify the caller is a loan contract (`_isLoanContract(caller)``==true`).

```solidity
//src/lib/loans/LoanManager.sol
    modifier onlyAcceptedCallers() {
        if (!_acceptedCallers.contains(msg.sender)) {
            revert CallerNotAccepted();
        }
        _;
    }
```

When a liquidator calls `validateOffer`, they can provide a fabricated `bytes calldata _offer` and `uint256 _protocolFee` bypassing additional checks and state accounting in a loan contract. For example, in MultiSourceLoan.sol- `emitLoan`, [extra checks are implemented](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L124) on `LoanExecutionData` to verify borrower and lender signatures and offer expiration timestamp as well as [transfer collateral NFT tokens](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L153) and [recoding loan to storage](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L155). All of the above can be skipped if a liquidator directly call `validateOffer` and modify `__outstandingValues` without token transfer.

### Recommended Mitigation Steps

In `Pool::validateOffer`, consider adding a check to ensure `_isLoanContract(msg.sender)``==true`.

### Assessed type

Invalid Validation

**[0xend (Gondi) acknowledged and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/41#issuecomment-2067341452):**
 > This is a low one given these contracts must all live within our ecosystem and be whitelisted. Given there's already that trust assumption, not doing that check to save some gas on an extra state read.

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/41#issuecomment-2067725596):**
 > > This is a low one given these contracts must all live within our ecosystem and be whitelisted.
> 
> That makes sense. However, I'm judging this based on the info that was present to the wardens in the README and docs. Given that that trust assumption wasn't noted there I'm going to sustain Medium severity.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Check `loanContract`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/105), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/75) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/28).

***

## [[M-11] `AuctionLoanLiquidator#placeBid` can be DoS](https://github.com/code-423n4/2024-04-gondi-findings/issues/37)
*Submitted by [zhaojie](https://github.com/code-423n4/2024-04-gondi-findings/issues/37), also found by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/8)*

The attacker performs a DoS attack on the `Bid` function, causing other users to be unable to participate and eventually obtaining the NFT at a low price.

### Proof of Concept

The `placeBid` function requires each bid to increase by 5% from the original, locking in for a period of time after each bid.

```solidity
function placeBid(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        external
        nonReentrant
        returns (Auction memory)
    {
        _placeBidChecks(_nftAddress, _tokenId, _auction, _bid);

        uint256 currentHighestBid = _auction.highestBid;
        // MIN_INCREMENT_BPS = 10000, _BPS = 500 , add 5%
        if (_bid == 0 || (currentHighestBid.mulDivDown(_BPS + MIN_INCREMENT_BPS, _BPS) >= _bid)) {
            revert MinBidError(_bid);
        }

        uint256 currentTime = block.timestamp;
        uint96 expiration = _auction.startTime + _auction.duration;
@>      uint96 withMargin = _auction.lastBidTime + _MIN_NO_ACTION_MARGIN;
        uint96 max = withMargin > expiration ? withMargin : expiration;
        if (max < currentTime && currentHighestBid > 0) {
            revert AuctionOverError(max);
        }
        .....
    }
```

The problem here is that if the initial price increases from a very small value, the second increase in percentage only needs to be a very small amount. For example: 100 wei -> 105 wei -> 110 wei.

So an attacker can start with a small bid and keep growing slowly. Because of the time lock, other users cannot participate for a period of time. Normal users must wait until the time lock is over and the transaction needs to be executed before the attacker.

If normal users are unable to participate in the bidding, the attacker can obtain the auction item (NFT) at a very low price.

### Tools Used

VScode

### Recommended Mitigation Steps

```diff
function placeBid(.....){
+       require (_bid > MIN_BID);
}
```

### Assessed type

DoS

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/37#issuecomment-2063819071):**
 > Given that auction duration is 3 days front-running every single tx in that timeframe isn't going to be easy for the attacker. Considering Medium.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/37#issuecomment-2067348640):**
 > We have a check that for an auction to be settled it also requires the last bid to be at least 10' old (to avoid someone sniping at the very end). Given this, someone doing this attack, would actually have to continue going for an indiscriminate amount of time since honest players would be able to bid and extend it.
> 
> I think this is Low/Medium.

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/37#issuecomment-2067727100):**
 > The attack seems very unlikely, but given that the impact can be quite high, I'm sustaining Medium severity.

**[0xend (Gondi) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/37#issuecomment-2067773664):**
 > https://github.com/pixeldaogg/florida-contracts/pull/377
> 
> Starting with a min based on principle to make sure it's meaningful.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> There's a min bid now. This + the min improvement invalidates DoS.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/106) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/76).

***

## [[M-12] `Pool.getMinTimeBetweenWithdrawalQueues` current calculations may not be sufficient ](https://github.com/code-423n4/2024-04-gondi-findings/issues/23)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/23)*

`getMinTimeBetweenWithdrawalQueues` is very important for `Pool`. If `getMinTimeBetweenWithdrawalQueues` is too small, `pendingQueues` will be overwritten too early, and when `Loan` pays off, it won't be able to find the corresponding `queues`.

So we will calculate `getMinTimeBetweenWithdrawalQueues` by `MaxDuration + _LOAN_BUFFER_TIME` to make sure it won't be overwritten too early.

Currently: `_LOAN_BUFFER_TIME = 7 days`
Similarly: `LiquidationHandler.MAX_AUCTION_DURATION = 7 days`

So `getMinTimeBetweenWithdrawalQueues` is sufficient if the bidding is done within the time period. However, less consideration is given to the presence of `AuctionLoanLiquidator._MIN_NO_ACTION_MARGIN` and the bidding can be delayed.

```solidity
    function placeBid(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        external
        nonReentrant
        returns (Auction memory)
    {
...
        uint256 currentTime = block.timestamp;
        uint96 expiration = _auction.startTime + _auction.duration;
        uint96 withMargin = _auction.lastBidTime + _MIN_NO_ACTION_MARGIN;
@>      uint96 max = withMargin > expiration ? withMargin : expiration;
        if (max < currentTime && currentHighestBid > 0) {
            revert AuctionOverError(max);
        }
```

If the bidding is intense, it may be delayed > `_MIN_NO_ACTION_MARGIN =10 minutes`, or even longer. So `getMinTimeBetweenWithdrawalQueues` may not be enough. Suggest adding an extra day: `MaxDuration + _LOAN_BUFFER_TIME + 3 days`.

### Impact

`getMinTimeBetweenWithdrawalQueues` is not large enough causing `pendingQueues` to be overwritten prematurely.

### Recommended Mitigation

```diff
contract Pool is ERC4626, InputChecker, IPool, IPoolWithWithdrawalQueues, LoanManager, ReentrancyGuard {
...

    /// @dev Used in case loans might have a liquidation, then the extension is upper bounded by maxDuration + liq time.
-   uint256 private constant _LOAN_BUFFER_TIME = 7 days;
+   uint256 private constant _LOAN_BUFFER_TIME = 10 days;
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/23#event-12545568687)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Limit auction extensions.

**Status:** Unmitigated. Full details in reports from [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/30), and also included in the [Mitigation Review](#mitigation-review) section below.

***

## [[M-13] `confirmBaseInterestAllocator()` change `BaseInterestAllocator` may pay large `getReallocationBonus`](https://github.com/code-423n4/2024-04-gondi-findings/issues/22)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/22)*

`owner` can submit `getPendingBaseInterestAllocator` first, and then anyone can enable it by `confirmBaseInterestAllocator()`.

```solidity
    function confirmBaseInterestAllocator(address _newBaseInterestAllocator) external {
        address cachedAllocator = getBaseInterestAllocator;
        if (cachedAllocator != address(0)) {
            if (getPendingBaseInterestAllocatorSetTime + UPDATE_WAITING_TIME > block.timestamp) {
                revert TooSoonError();
            }
            if (getPendingBaseInterestAllocator != _newBaseInterestAllocator) {
                revert InvalidInputError();
            }
@>          IBaseInterestAllocator(cachedAllocator).transferAll();
            asset.approve(cachedAllocator, 0);
        }
        asset.approve(_newBaseInterestAllocator, type(uint256).max);

        getBaseInterestAllocator = _newBaseInterestAllocator;
        getPendingBaseInterestAllocator = address(0);
        getPendingBaseInterestAllocatorSetTime = type(uint256).max;

        emit BaseInterestAllocatorSet(_newBaseInterestAllocator);
    }
```

The current logic is:

1. Take all the balance of the old `BaseInterestAllocator` and put it in `Pool`.
2. Change `getBaseInterestAllocator` to the new `BaseInterestAllocator`.

If the old `BaseInterestAllocator` already has a large balance, the balance of the Pool will increase dramatically. Subsequent users executing `reallocate()` will get a big bonus `getReallocationBonus`.

```solidity
    function reallocate() external nonReentrant returns (uint256) {
        (uint256 currentBalance, uint256 targetIdle) = _reallocate();
        uint256 delta = currentBalance > targetIdle ? currentBalance - targetIdle : targetIdle - currentBalance;
@>      uint256 shares = delta.mulDivDown(totalSupply * getReallocationBonus, totalAssets() * _BPS);

        _mint(msg.sender, shares);

        emit Reallocated(delta, shares);

        return shares;
    }
```

Assuming old `BaseInterestAllocator` balance: 1 M:
`shares = 1 M * (1 - optimalIdleRange.mid) * totalSupply * getReallocationBonus / totalAssets()`

### Impact

After change, `BaseInterestAllocator` may pay large `getReallocationBonus`.

### Recommended Mitigation

Execute `_reallocate()` in the `confirmBaseInterestAllocator()` method without paying any `getReallocationBonus`.

```diff
    function confirmBaseInterestAllocator(address _newBaseInterestAllocator) external {
        address cachedAllocator = getBaseInterestAllocator;
        if (cachedAllocator != address(0)) {
            if (getPendingBaseInterestAllocatorSetTime + UPDATE_WAITING_TIME > block.timestamp) {
                revert TooSoonError();
            }
            if (getPendingBaseInterestAllocator != _newBaseInterestAllocator) {
                revert InvalidInputError();
            }
            IBaseInterestAllocator(cachedAllocator).transferAll();
            asset.approve(cachedAllocator, 0);
        }
        asset.approve(_newBaseInterestAllocator, type(uint256).max);

        getBaseInterestAllocator = _newBaseInterestAllocator;
        getPendingBaseInterestAllocator = address(0);
        getPendingBaseInterestAllocatorSetTime = type(uint256).max;
+       if (cachedAllocator != address(0)) {
+             _reallocate();
+       }
        emit BaseInterestAllocatorSet(_newBaseInterestAllocator);
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/22#event-12545571872)**

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/22#issuecomment-2067732464):**
 > Marking as Medium since it'll only take the fee part (which is only a small percentage I guess). I guess also the allocator isn't going to change very often.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Proactively reallocate (we got rid of the bonus though).

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/108) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/31).

***

## [[M-14] `loanLiquidation()` calculation of interest is not accurate](https://github.com/code-423n4/2024-04-gondi-findings/issues/20)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/20)*

`loanLiquidation()`: The calculated interest codes are as follows：

```solidity
    function loanLiquidation(
        uint256 _loanId,
        uint256 _principalAmount,
        uint256 _apr,
        uint256,
        uint256 _protocolFee,
        uint256 _received,
        uint256 _startTime
    ) external override onlyAcceptedCallers {
        uint256 netApr = _netApr(_apr, _protocolFee);
        uint256 interestEarned = _principalAmount.getInterest(netApr, block.timestamp - _startTime);
@>      uint256 fees = IFeeManager(getFeeManager).processFees(_received, 0);
        getCollectedFees += fees;
        _loanTermination(msg.sender, _loanId, _principalAmount, netApr, interestEarned, _received - fees);
    }
...

contract FeeManager is IFeeManager, TwoStepOwned {
...
    function processFees(uint256 _principal, uint256 _interest) external view returns (uint256) {
        /// @dev cached
        Fees memory __fees = _fees;
        return _principal.mulDivDown(__fees.managementFee, PRECISION)
            + _interest.mulDivDown(__fees.performanceFee, PRECISION);
    }
```

The above code takes all of `_received` as the principal and gives it to `IFeeManager` to calculate. But the amount received from the bidding is not always less than the principal, it may be more than the principal, and this part should be calculated as `interest`.

### Impact

When `received` is greater than the principal, `fees` is not correct.

### Recommended Mitigation

```diff
    function loanLiquidation(
        uint256 _loanId,
        uint256 _principalAmount,
        uint256 _apr,
        uint256,
        uint256 _protocolFee,
        uint256 _received,
        uint256 _startTime
    ) external override onlyAcceptedCallers {
        uint256 netApr = _netApr(_apr, _protocolFee);
        uint256 interestEarned = _principalAmount.getInterest(netApr, block.timestamp - _startTime);
-       uint256 fees = IFeeManager(getFeeManager).processFees(_received, 0);
+       uint256 fees;
+       if (_received > _principalAmount) {
+           fees = IFeeManager(getFeeManager).processFees(_principalAmount, _received - _principalAmount);
+       }else {
+           fees = IFeeManager(getFeeManager).processFees(_received, 0);
+       }
        getCollectedFees += fees;
        _loanTermination(msg.sender, _loanId, _principalAmount, netApr, interestEarned, _received - fees);
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/20#event-12545577238)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Corrected calculation of fees as suggested.


**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/109), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/79) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/32).

***

## [[M-15] `confirmUnderwriter()` need to recalculate `getMinTimeBetweenWithdrawalQueues`](https://github.com/code-423n4/2024-04-gondi-findings/issues/17)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/17)*

`getMinTimeBetweenWithdrawalQueues` is very important for `Pool`. If `getMinTimeBetweenWithdrawalQueues` is too small, `pendingQueues` will be overwritten too early, and when `Loan` pays off, it won't be able to find the corresponding `queues`.

So we will calculate `getMinTimeBetweenWithdrawalQueues` by `MaxDuration + _LOAN_BUFFER_TIME` to make sure it won't be overwritten too early.

```solidity
    constructor(
        address _feeManager,
        address _offerHandler,
        uint256 _waitingTimeBetweenUpdates,
        OptimalIdleRange memory _optimalIdleRange,
        uint256 _maxTotalWithdrawalQueues,
        uint256 _reallocationBonus,
        ERC20 _asset,
        string memory _name,
        string memory _symbol
    ) ERC4626(_asset, _name, _symbol) LoanManager(tx.origin, _offerHandler, _waitingTimeBetweenUpdates) {

....

@>      getMinTimeBetweenWithdrawalQueues = (IPoolOfferHandler(_offerHandler).getMaxDuration() + _LOAN_BUFFER_TIME)
            .mulDivUp(1, _maxTotalWithdrawalQueues);
```

But switching the new `getUnderwriter/_offerHandler` doesn't recalculate the `getMinTimeBetweenWithdrawalQueues`.

```solidity
    function confirmUnderwriter(address __underwriter) external onlyOwner {
        if (getPendingUnderwriterSetTime + UPDATE_WAITING_TIME > block.timestamp) {
            revert TooSoonError();
        }
        if (getPendingUnderwriter != __underwriter) {
            revert InvalidInputError();
        }

@>      getUnderwriter = __underwriter;
        getPendingUnderwriter = address(0);
        getPendingUnderwriterSetTime = type(uint256).max;

        emit UnderwriterSet(__underwriter);
    }
```

This may break the expectation of `getMinTimeBetweenWithdrawalQueues`, and the new `getUnderwriter.getMaxDuration` is larger than the old one; which may cause `pendingQueues` to be overwritten prematurely.

### Impact

The new `getUnderwriter.getMaxDuration` is larger than the old one, which may cause `pendingQueues` to be overwritten prematurely.

### Recommended Mitigation

`Pool` overrides `confirmUnderwriter()` with an additional recalculation of `getMinTimeBetweenWithdrawalQueues` and must not be smaller than the old one, to avoid premature overwriting of the previous one.

```diff
contract Pool is ERC4626, InputChecker, IPool, IPoolWithWithdrawalQueues, LoanManager, ReentrancyGuard {
-   uint256 public immutable getMinTimeBetweenWithdrawalQueues;
+   uint256 public getMinTimeBetweenWithdrawalQueues;
...
+   function confirmUnderwriter(address __underwriter) external override onlyOwner {
+           super.confirmUnderwriter(__underwriter);
+           uint256 newMinTime = (IPoolOfferHandler(__underwriter).getMaxDuration() + _LOAN_BUFFER_TIME)
+            .mulDivUp(1, _maxTotalWithdrawalQueues);
+           require(newMinTime >= getMinTimeBetweenWithdrawalQueues,"invalid");
+           getMinTimeBetweenWithdrawalQueues = newMinTime;
+    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/17#event-12545582338)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added check (`maxDuration` cannot be longer).

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/110), [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/33) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/80).

***

## [[M-16] `distribute()` uses the wrong end time to break `maxSeniorRepayment`'s expectations](https://github.com/code-423n4/2024-04-gondi-findings/issues/16)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/16)*

When the bid amount is not enough, the `lender` will be repaid in order of `tranche[]`.
In order to minimize the risk, the user can specify `maxSeniorRepayment` to avoid the risk to some extent, and put himself in a position of higher repayment priority. At the same time `emitLoan()` checks `maxSeniorRepayment` for the `emitLoan()`.

`emitLoan()` -> `_processOffersFromExecutionData()` -> `_checkOffer()`

```solidity
    function _processOffersFromExecutionData(
        address _borrower,
        address _principalReceiver,
        address _principalAddress,
        address _nftCollateralAddress,
        uint256 _tokenId,
        uint256 _duration,
        OfferExecution[] calldata _offerExecution
    ) private returns (uint256, uint256[] memory, Loan memory, uint256) {
...
            uint256 amount = thisOfferExecution.amount;
            address lender = offer.lender;
            /// @dev Please note that we can now have many tranches with same `loanId`.
            tranche[i] = Tranche(loanId, totalAmount, amount, lender, 0, block.timestamp, offer.aprBps);
            totalAmount += amount;
@>          totalAmountWithMaxInterest += amount + amount.getInterest(offer.aprBps, _duration);
...

    function _checkOffer(
        LoanOffer calldata _offer,
        address _principalAddress,
        address _nftCollateralAddress,
        uint256 _amountWithInterestAhead
    ) private pure {
        if (_offer.principalAddress != _principalAddress || _offer.nftCollateralAddress != _nftCollateralAddress) {
            revert InvalidAddressesError();
        }
@>      if (_amountWithInterestAhead > _offer.maxSeniorRepayment) {
            revert InvalidTrancheError();
        }
    }
```

`totalAmountWithMaxInterest` is computed using `loan._duration`. But when the bidding ends and the distribution is done in `LiquidationDistributor.distribute()`, the current time is used to calculate `Interest`.

```solidity
    function distribute(uint256 _proceeds, IMultiSourceLoan.Loan calldata _loan) external {
        uint256[] memory owedPerTranche = new uint256[](_loan.tranche.length);
        uint256 totalPrincipalAndPaidInterestOwed = _loan.principalAmount;
        uint256 totalPendingInterestOwed = 0;
        for (uint256 i = 0; i < _loan.tranche.length;) {
            IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
            uint256 pendingInterest =
@>              thisTranche.principalAmount.getInterest(thisTranche.aprBps, block.timestamp - thisTranche.startTime);
            totalPrincipalAndPaidInterestOwed += thisTranche.accruedInterest;
            totalPendingInterestOwed += pendingInterest;
            owedPerTranche[i] += thisTranche.principalAmount + thisTranche.accruedInterest + pendingInterest;
            unchecked {
                ++i;
            }
        }
```

Because bidding takes a certain amount of time (`~3-7 days`), using `block.timestamp - thisTranche.startTime` will be larger than expected! Correctly should use: (`loan.startTime + loan.duration - thisTranche.startTime`) to calculate the `interest`.

This leads to the problem that if there are not enough funds, the front `lender` will get a larger repayment than expected, breaking the back `lender`'s initial expectation of `maxSeniorRepayment`.

### Impact

If there are not enough funds, the initial expectation of `maxSeniorRepayment` may be broken.

### Recommended Mitigation

```diff
    function distribute(uint256 _proceeds, IMultiSourceLoan.Loan calldata _loan) external {
        uint256[] memory owedPerTranche = new uint256[](_loan.tranche.length);
        uint256 totalPrincipalAndPaidInterestOwed = _loan.principalAmount;
        uint256 totalPendingInterestOwed = 0;
+      uint256 loanExpireTime = _loan.startTime + _loan.duration;
        for (uint256 i = 0; i < _loan.tranche.length;) {
            IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
            uint256 pendingInterest =
-               thisTranche.principalAmount.getInterest(thisTranche.aprBps, block.timestamp - thisTranche.startTime);
+               thisTranche.principalAmount.getInterest(thisTranche.aprBps, loanExpireTime - thisTranche.startTime);
            totalPrincipalAndPaidInterestOwed += thisTranche.accruedInterest;
            totalPendingInterestOwed += pendingInterest;
            owedPerTranche[i] += thisTranche.principalAmount + thisTranche.accruedInterest + pendingInterest;
            unchecked {
                ++i;
            }
        }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/16#event-12543522584)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Changed to loan end time (instead of current timestamp).

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/111), [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/81).

***

## [[M-17] `loan.hash()` does not contain `protocolFee`](https://github.com/code-423n4/2024-04-gondi-findings/issues/15)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/15), also found by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/81) and [minhquanym](https://github.com/code-423n4/2024-04-gondi-findings/issues/53)*

The current `IMultiSourceLoan.loop.hash()` does not contain `protocolFee`:

```solidity
    function emitLoan(LoanExecutionData calldata _loanExecutionData)
        external
        nonReentrant
        returns (uint256, Loan memory)
    {
...
@>      _loans[loanId] = loan.hash();
        emit LoanEmitted(loanId, offerIds, loan, totalFee);

        return (loanId, loan);
    }

    function hash(IMultiSourceLoan.Loan memory _loan) internal pure returns (bytes32) {
        bytes memory trancheHashes;
        for (uint256 i; i < _loan.tranche.length;) {
            trancheHashes = abi.encodePacked(trancheHashes, _hashTranche(_loan.tranche[i]));
            unchecked {
                ++i;
            }
        }
        return keccak256(
            abi.encode(
                _MULTI_SOURCE_LOAN_HASH,
                _loan.borrower,
                _loan.nftCollateralTokenId,
                _loan.nftCollateralAddress,
                _loan.principalAddress,
                _loan.principalAmount,
                _loan.startTime,
                _loan.duration,
@>              //@audit miss protocolFee
                keccak256(trancheHashes)
            )
        );
    }

   struct Loan {
        address borrower;
        uint256 nftCollateralTokenId;
        address nftCollateralAddress;
        address principalAddress;
        uint256 principalAmount;
        uint256 startTime;
        uint256 duration;
        Tranche[] tranche;
@>      uint256 protocolFee;
    }
```

Then, you can specify `protocolFee` arbitrarily in many methods, but the `_baseLoanChecks()` security check doesn't `revert`.

```solidity
    function _baseLoanChecks(uint256 _loanId, Loan memory _loan) private view {
@>      if (_loan.hash() != _loans[_loanId]) {
            revert InvalidLoanError(_loanId);
        }
        if (_loan.startTime + _loan.duration < block.timestamp) {
            revert LoanExpiredError();
        }
    }
```

Example: `repayLoan(loadn.protocolFee=0)` to escape `fees` and cause a `LoanManager` accounting error. `refinancePartial()/refinanceFull()` can also specify the wrong `fees` to skip the fees.

### Impact

The loan hash does not contain a `protocolFee`, leading to an arbitrary `protocolFee` that can be specified to escape `fees` or cause an accounting error.

### Recommended Mitigation

```diff
    function hash(IMultiSourceLoan.Loan memory _loan) internal pure returns (bytes32) {
        bytes memory trancheHashes;
        for (uint256 i; i < _loan.tranche.length;) {
            trancheHashes = abi.encodePacked(trancheHashes, _hashTranche(_loan.tranche[i]));
            unchecked {
                ++i;
            }
        }
        return keccak256(
            abi.encode(
                _MULTI_SOURCE_LOAN_HASH,
                _loan.borrower,
                _loan.nftCollateralTokenId,
                _loan.nftCollateralAddress,
                _loan.principalAddress,
                _loan.principalAmount,
                _loan.startTime,
                _loan.duration, 
                keccak256(trancheHashes),
+               _loan.protocolFee
            )
        );
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/15#event-12543524712)**

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/15#issuecomment-2068016928):**
 > Avoiding fees is just a Medium. For the accounting error, I'll need more proof that this can lead to something significant to mark this as High.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Added field in hash.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/112), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/82) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/35).

***

## [[M-18] `distribute()` when can't repay all lenders, may lack of notification to `LoanManager` for accounting](https://github.com/code-423n4/2024-04-gondi-findings/issues/10)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/10)*

The `LiquidationDistributor` is used to distribute funds after an auction. When the auction amount is insufficient, lenders are repaid in sequence.

```solidity
    function distribute(uint256 _proceeds, IMultiSourceLoan.Loan calldata _loan) external {
...
        if (_proceeds > totalPrincipalAndPaidInterestOwed + totalPendingInterestOwed) {
            for (uint256 i = 0; i < _loan.tranche.length;) {
                IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
                _handleTrancheExcess(
                    _loan.principalAddress,
                    thisTranche,
                    msg.sender,
                    _proceeds,
                    totalPrincipalAndPaidInterestOwed + totalPendingInterestOwed
                );
                unchecked {
                    ++i;
                }
            }
        } else {
@>          for (uint256 i = 0; i < _loan.tranche.length && _proceeds > 0;) {
                IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
                _proceeds = _handleTrancheInsufficient(
                    _loan.principalAddress, thisTranche, msg.sender, _proceeds, owedPerTranche[i]
                );
                unchecked {
                    ++i;
                }
            }
        }
    }
```

The code snippet above introduces a condition `_proceeds > 0` to terminate the loop when there's no remaining balance in `_proceeds`, thereby preventing further execution of `_handleTrancheInsufficient()`.

However, this approach creates an issue. If the subsequent lender is a `LoanManager`, it won't be notified for accounting via `_handleTrancheInsufficient()` -> `_handleLoanManagerCall()` -> `LoanManager(_tranche.lender).loanLiquidation()`.

Although no funds can be repaid, accounting is still necessary to notice and prevent incorrect accounting, causing inaccuracies in `totalAssets()` and continued accumulation of interest.
This outstanding debt should be shared among current users and prevent it from persisting as bad debt.

### Impact

Failure to notify `LoanManager.loanLiquidation()` may result in accounting inaccuracies.

### Recommended Mitigation

```diff
    function distribute(uint256 _proceeds, IMultiSourceLoan.Loan calldata _loan) external {
...
        } else {
-           for (uint256 i = 0; i < _loan.tranche.length && _proceeds > 0;) {
+           for (uint256 i = 0; i < _loan.tranche.length;) {
                IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
                _proceeds = _handleTrancheInsufficient(
                    _loan.principalAddress, thisTranche, msg.sender, _proceeds, owedPerTranche[i]
                );
                unchecked {
                    ++i;
                }
            }
        }
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/10#event-12543550109)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Always call `loanManager` (even if 0 proceeds).

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/113), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/83) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/36).

***

## [[M-19] Bidders might lose funds due to possible racing condition between `settleWithBuyout` and `placeBid`](https://github.com/code-423n4/2024-04-gondi-findings/issues/6)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/6), also found by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/34)*

In `AuctionWithBuyoutLoanLiquidator.sol`, `settleWithBuyout` and `placeBid` are allowed at an overlapping timestamp (`_auction.startTime + _timeForMainLenderToBuy`). This allows `settleWithBuyout` and `placeBid` to be settled at the same block.

When `placeBid` tx settles at `_auction.startTime + _timeForMainLenderToBuy` before `settleWithBuyout` tx, the bidder will lose their funds. Because `settleWithBuyout` will always assume no bids are placed, it will directly transfer out the collateral NFT token and [delete the auction data](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionWithBuyoutLoanLiquidator.sol#L101) from storage.

```solidity
    function settleWithBuyout(
        address _nftAddress,
        uint256 _tokenId,
        Auction calldata _auction,
        IMultiSourceLoan.Loan calldata _loan
    ) external nonReentrant {
...
        uint256 timeLimit = _auction.startTime + _timeForMainLenderToBuy;
 |>       if (timeLimit < block.timestamp) {
            revert OptionToBuyExpiredError(timeLimit);
        }
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionWithBuyoutLoanLiquidator.sol#L63C1-L66C10>

```solidity
    function _placeBidChecks(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        internal
        view
        override
    {
...
        uint256 timeLimit = _auction.startTime + _timeForMainLenderToBuy;
|>        if (timeLimit > block.timestamp) {
            revert OptionToBuyStilValidError(timeLimit);
        }
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionWithBuyoutLoanLiquidator.sol#L129>

### Recommended Mitigation Steps

Consider to only allow buyout strictly before the timeLimit `if (timeLimit <= block.timestamp) {//revert`.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/6#event-12543553998)**

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Strict to `>=`.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/114), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/84) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/37).

***

## [[M-20] Hardcoded incorrect `getLidoData` timestamp, resulting in incorrect base point `Apr. Loans` can be validated with a substantially low `baseRate` interest ](https://github.com/code-423n4/2024-04-gondi-findings/issues/3)
*Submitted by [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/3)*

In `LidoEthBaseInterestAllocator.sol`, [`getLidoData`](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/LidoEthBaseInterestAllocator.sol#L62) is initialized with an incorrect timestamp, causing subsequent `baseApr` to be incorrect.

In constructor, `getLidoData` is initialized with `0` timestamp. This should be `block.timestamp` instead. As a result, `baseApr` updates will be much lower:

```solidity
//src/lib/pools/LidoEthBaseInterestAllocator.sol

    struct LidoData {
        uint96 lastTs;
        uint144 shareRate;
        uint16 aprBps;
    }
...
    constructor(
        address _pool,
        address payable __curvePool,
        address payable __weth,
        address __lido,
        uint256 _currentBaseAprBps,
        uint96 _lidoUpdateTolerance
    ) Owned(tx.origin) {
...
          //@audit 0-> block.timestamp
|>        getLidoData = LidoData(0, uint144(_currentShareRate()), uint16(_currentBaseAprBps));
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/LidoEthBaseInterestAllocator.sol#L62>

For example, in `_updateLidoValue()`, `_lidoData.aprBps` is [calculated based on delta shareRate, divided by delta timespan](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/LidoEthBaseInterestAllocator.sol#L162-L164). (`_BPS * _SECONDS_PER_YEAR * (shareRate - _lidoData.shareRate) / _lidoData.shareRate/ (block.timestamp - _lidoData.lastTs)`) `shareRate` and `_lidoData.shareRate` are associated with current timestamp, and deployment timestamp respectively. But timespan would be (`block.timestamp - 0`). This deflated `_lidoData.aprBps` value, which is used to [validate Loan offers](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L400) in Pool.sol during loan initiation.

In `PoolOfferHandler.sol`, this allows loan offers with substantially low `aprBps` to pass the [minimal apr check](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/PoolOfferHandler.sol#L165).

```solidity
//src/lib/pools/PoolOfferHandler.sol
    function validateOffer(uint256 _baseRate, bytes calldata _offer)
        external
        view
        override
        returns (uint256 principalAmount, uint256 aprBps)
    {
...
        if (offerExecution.offer.aprBps < _baseRate + aprPremium || aprPremium == 0) {
            revert InvalidAprError();
        }
...
```

<https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/PoolOfferHandler.sol#L165>

Loans with invalid aprs can be created.

### Recommended Mitigation Steps

Use `block.timestamp` to initialize `getLidoData`.

### Assessed type

Error

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/3#event-12543561677)**

**[0xA5DF (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/3#issuecomment-2067735146):**
 > Marking as Medium since this only impacts interest and it's limited to the initial phase of the contract.

**[Gondi mitigated](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#mitigation-of-high--medium-severity-issues):**
> Set right value for `getLidoData` timestamp.

**Status:** Mitigation confirmed. Full details in reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/115), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/85) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/38).

***

# Low Risk and Non-Critical Issues

For this audit, 3 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-04-gondi-findings/issues/70) by **minhquanym** received the top score from the judge.

*The following wardens also submitted reports: [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/82) and [bin2chen](https://github.com/code-423n4/2024-04-gondi-findings/issues/74).*

## [01] No need to approve `__aavePool` to spend `__aToken`

[AaveUsdcBaseInterestAllocator.sol#L44](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/AaveUsdcBaseInterestAllocator.sol#L44)

### Details

The AavePool can burn the `aToken` directly without any allowance from burner address. So the call to approve `aToken` in the constructor of `AaveUsdcBaseInterestAllocator` contract is unnecessary.

```solidity
constructor(address _pool, address __aavePool, address __usdc, address __aToken) Owned(tx.origin) {
    if (address(Pool(_pool).asset()) != address(__usdc)) {
        revert InvalidPoolError();
    }
    getPool = _pool;
    _aavePool = __aavePool;
    _usdc = __usdc;
    _aToken = __aToken;
    ERC20(__usdc).approve(__aavePool, type(uint256).max);
     // @audit No need to approve aToken
    ERC20(__aToken).approve(__aavePool, type(uint256).max);
}
```

Check out the AavePool code [here](https://polygonscan.com/address/0x1ed647b250e5b6d71dc7b25806f44c33f5658f71#code#F1#L196).

## [02] Open TODOs

[AaveUsdcBaseInterestAllocator#L90](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/AaveUsdcBaseInterestAllocator.sol#L90)

[AaveUsdcBaseInterestAllocator.sol#L16](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/AaveUsdcBaseInterestAllocator.sol#L16)

[AuctionWithBuyoutLoanLiquidator.sol#L61](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionWithBuyoutLoanLiquidator.sol#L61)

[LoanManager.sol#L10](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L10)

[ValidatorHelpers.sol#L4](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/ValidatorHelpers.sol#L4)


### Details

There are a lot of open TODOs in the codebase. They indicate there are some missing functionalities needed to be implemented. For example:

```solidity
function claimRewards() external {
    /// TODO: getIncentivesController
}
```

## [03] Function `burnAndWithdraw()` does not withdraw old ERC721s

[UserVault.sol#L125](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/UserVault.sol#L125)

### Details

The function `burnAndWithdraw()` should burn the vault and withdraw all assets in that vault. However, the old ERC721 is not withdrawn.

```solidity
function burnAndWithdraw( // @audit Not withdraw old ERC721
    uint256 _vaultId,
    address[] calldata _collections,
    uint256[] calldata _tokenIds,
    address[] calldata _tokens
) external {
    _thisBurn(_vaultId, msg.sender);
    for (uint256 i = 0; i < _collections.length;) {
        _withdrawERC721(_vaultId, _collections[i], _tokenIds[i]);
        unchecked {
            ++i;
        }
    }
    for (uint256 i = 0; i < _tokens.length;) {
        _withdrawERC20(_vaultId, _tokens[i]);
        unchecked {
            ++i;
        }
    }
    _withdrawEth(_vaultId);
}
```

## [04] Function in `BytesLib` could revert with no error message 

[BytesLib.sol](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/BytesLib.sol)

### Details

All functions in `BytesLib` have some require check for overflow. However, these checks will only work with Solidity version `< 0.8` because Solidity 0.8 already has some overflow check. 

For example, in the function `slice()`, in the case overflow actually happens in the first check, the calculation `_length + 31` is already revert by solidity 0.8 before checking the condition in the require.

```solidity
function slice(bytes memory _bytes, uint256 _start, uint256 _length) internal pure returns (bytes memory) {
    require(_length + 31 >= _length, "slice_overflow");
    require(_start + _length >= _start, "slice_overflow"); // @audit These calculation will revert with solidity 0.8
    require(_bytes.length >= _start + _length, "slice_outOfBounds");
    ...
}
```

## [05] `setProtocolFee()` can be called multiple times to spam event emission

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/WithProtocolFee.sol#L73

### Details

Function `setProtocolFee()` does not reset the pending value (`_pendingProtocolFee`). As the result, `setProtocolFee()` can be called infinite times. Even though the protocol fee cannot be changed, the event will be emit multiple times.

```solidity
// @audit setProtocolFee can be called again since _pendingProtocolFeeSetTime is not reset
function setProtocolFee() external virtual { 
    _setProtocolFee();
}

function _setProtocolFee() internal {
    if (block.timestamp < _pendingProtocolFeeSetTime + FEE_UPDATE_NOTICE) {
        revert TooSoonError();
    }
    ProtocolFee memory protocolFee = _pendingProtocolFee;
    _protocolFee = protocolFee;

    emit ProtocolFeeUpdated(protocolFee);
}
```

## [06] Repayment and liquidation could be blocked if token has a callhook to receiver

[AuctionLoanLiquidator.sol#L285](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L285)

[LiquidationDistributor.sol#L88](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/LiquidationDistributor.sol#L88)

[MultiSourceLoan.sol#L946](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L946)

### Details

Some tokens like ERC777 has a callhook on receiver address. If these tokens are used in a loan, it could allow attacker to force liquidation/repayment to fail. For example, the function `settleAuction()` transfer the fee to originator. The originator could be an contract that will revert when receiving token transfer, making it impossible for auction to settle.
```solidity
asset.safeTransfer(_auction.originator, triggerFee); // @audit can revert if the token has callhook on receiver
asset.safeTransfer(msg.sender, triggerFee);
```

## [07] Wrong event emission in `finalUpdateMultiSourceLoanAddress()`

[PurchaseBundler.sol#L238-L247](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/callbacks/PurchaseBundler.sol#L238-L247)

### Details

Wrong variable is used when emit `MultiSourceLoanUpdated` event.

```solidity
function finalUpdateMultiSourceLoanAddress(address _newAddress) external onlyOwner {
    if (_pendingMultiSourceLoanAddress != _newAddress) {
        revert InvalidAddressUpdateError();
    }

    _multiSourceLoan = MultiSourceLoan(_pendingMultiSourceLoanAddress);
    _pendingMultiSourceLoanAddress = address(0);

    // @audit wrong event, _pendingMultiSourceLoanAddress is already reset to 0
    emit MultiSourceLoanUpdated(_pendingMultiSourceLoanAddress);
}
```

## [08] `addCallers()` does not check `_callers.length == pendingCallers.length`

[LoanManager.sol#L80](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L80)

### Details

Function lacking check to ensure the pending list is the same as the list input by caller.

```solidity
function addCallers(PendingCaller[] calldata _callers) external onlyOwner {
    if (getPendingAcceptedCallersSetTime + UPDATE_WAITING_TIME > block.timestamp) {
        revert TooSoonError();
    }
    PendingCaller[] memory pendingCallers = getPendingAcceptedCallers; // @audit not check _callers.length == pendingCallers.length
    for (uint256 i = 0; i < _callers.length;) {
        ...
    }

    emit CallersAdded(_callers);
}
```

## [09] Partial refinance offer could be used in `refinanceFull()`

[MultiSourceLoan.sol#L162-L169](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L162-L169)

### Details

The function `refinanceFull()` does not verify the `_renegotiationOffer.trancheIndex` to ensure it includes all the indexes of the current loan.

```solidity
    function refinanceFull(
        RenegotiationOffer calldata _renegotiationOffer,
        Loan memory _loan,
        bytes calldata _renegotiationOfferSignature
    ) external nonReentrant returns (uint256, Loan memory) { // @audit not check _renegotiationOffer.trancheIndex.length = 0
        _baseLoanChecks(_renegotiationOffer.loanId, _loan);
        _baseRenegotiationChecks(_renegotiationOffer, _loan);
```

As a result, if a lender signs a partial refinance offer, others could use the same signature to call `refinanceFull()`. This could act against the lender's intention when signing the offer.

## [10] Owner can set `_multiSourceLoan` to `address(0)` directly without `updateMultiSourceLoanAddressFirst()`

[PurchaseBundler.sol#L238-L247](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/callbacks/PurchaseBundler.sol#L238-L247)

### Details

The `_pendingMultiSourceLoanAddress` has default value is `address(0)`. As the result, owner could always call `finalUpdateMultiSourceLoanAddress()` to set the `_multiSourceLoan` to `address(0)` without calling `updateMultiSourceLoanAddressFirst()` first.

```solidity
    function finalUpdateMultiSourceLoanAddress(address _newAddress) external onlyOwner { // @audit can set `_multiSourceLoan` to address(0) directly without `updateMultiSourceLoanAddressFirst()`
        if (_pendingMultiSourceLoanAddress != _newAddress) {
            revert InvalidAddressUpdateError();
        }

        _multiSourceLoan = MultiSourceLoan(_pendingMultiSourceLoanAddress);
        _pendingMultiSourceLoanAddress = address(0);

        emit MultiSourceLoanUpdated(_pendingMultiSourceLoanAddress);
    }
```

## [11] Slippage of stETH swap could make `validateOffer()` revert

[Pool.sol#L407-L413](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L407-L413)

### Details

The `MultiSourceLoan` contract calls the `validateOffer()` function to verify that the loan term has been approved by the Pool contract. This function also draws the necessary capital from the base interest allocator to ensure a sufficient balance for the loan.

As the pool's balance includes capital awaiting claim by the queues, it needs to verify that the pool has enough capital to fund the loan. If this isn't the case, and the principal exceeds the current balance, the function needs to reallocate part of it.

```solidity
if (principalAmount > undeployedAssets) {
    revert InsufficientAssetsError();
} else if (principalAmount > currentBalance) {
    IBaseInterestAllocator(getBaseInterestAllocator).reallocate( // @audit slippage of Lido swap could make the pool insufficient
        currentBalance, principalAmount - currentBalance, true
    );
}
```

However, the `reallocate()` function for the `LidoEthBaseInterestAllocator` performs a swap that could cause slippage. This could result in the contract still not having enough balance to provide the loan, even after calling `reallocate()`.

## [12] Modifier `onlyReadyForWithdrawal` is repeatedly execute when users withdraw multiple tokens

[UserVault.sol#L80-L85](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/UserVault.sol#L80-L85)

### Details

```solidity
modifier onlyReadyForWithdrawal(uint256 _vaultId) { // @audit Repeatedly checked when withdraw multiple tokens
    if (_readyForWithdrawal[_vaultId] != msg.sender) {
        revert NotApprovedError(_vaultId);
    }
    _;
}
```

The `onlyReadyForWithdrawal` modifier is used to check if the vault can be withdrawn and the permitted caller is call it. However, this check is performed in internal function, making it repeatedly call for the same `_vaultId` when users withdraw more than 1 token.

```solidity
function withdrawERC721s(uint256 _vaultId, address[] calldata _collections, uint256[] calldata _tokenIds)
    external
{
    ...
    for (uint256 i = 0; i < _collections.length;) {
        _withdrawERC721(_vaultId, _collections[i], _tokenIds[i]);
        unchecked {
            ++i;
        }
    }
}

function _withdrawERC721(uint256 _vaultId, address _collection, uint256 _tokenId)
    private
    onlyReadyForWithdrawal(_vaultId)
{
    ...
}
```

## [13] Should use defined variable in function `_checkValidators()`

[MultiSourceLoan.sol#L899-L901](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L899-L901)

```solidity
function _checkValidators(LoanOffer calldata _loanOffer, uint256 _tokenId) private {
    uint256 offerTokenId = _loanOffer.nftCollateralTokenId;
    // @audit Should use the cache value above
    if (_loanOffer.nftCollateralTokenId != 0) {
```

***

## [[14] Function `_checkStrictlyBetter()` does not check for `ImprovementMinimum`](https://github.com/code-423n4/2024-04-gondi-findings/issues/68)

*Note: At the judge’s request [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/70#issuecomment-2067964983), this downgraded issue from the same warden has been included in this report for completeness.*

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L835-L846

### Impact

The `ImprovementMinimum` defines the minimum improvement (in BPS) required for a strict improvement when users refinance an existing loan.

```solidity
struct ImprovementMinimum {
    uint256 principalAmount;
    uint256 interest;
    uint256 duration;
}
```

At deployment, its value is set as:

```solidity
ImprovementMinimum internal _minimum = ImprovementMinimum(500, 100, 100);
```

The code snippets above demonstrate that three improvements are required when users refinance: principal amount, interest, and loan duration. However, the function `_checkStrictlyBetter()` currently checks only the APR (interest) in `_checkTrancheStrictly()`. The other `principalAmount` and `endTime` are checked to be larger than the previous values but not checked for minimum improvement in the function `_checkStrictlyBetter()`.

### Proof of Concept

As you can see, the `_checkTrancheStrictly()` checks the APR to be improved by `__minimum.interest`. However, the duration is only checked to be `_offerEndTime < _loanEndTime` in `_checkStrictlyBetter()`.

```solidity
function _checkTrancheStrictly(
    bool _isStrictlyBetter,
    uint256 _currentAprBps,
    uint256 _targetAprBps,
    ImprovementMinimum memory __minimum
) private pure {
    /// @dev If _isStrictlyBetter is set, and the new apr is higher, then it'll underflow.
    if (
        _isStrictlyBetter
            && ((_currentAprBps - _targetAprBps).mulDivDown(_PRECISION, _currentAprBps) < __minimum.interest)
    ) {
        revert InvalidRenegotiationOfferError();
    }
}

// @audit not check ImprovementMinimum for principalAmount and endTime
if (
    (
        (_offerPrincipalAmount - _loanPrincipalAmount > 0)
            && (
                (_loanAprBps * _loanPrincipalAmount - _offerAprBps * _offerPrincipalAmount).mulDivDown(
                    _PRECISION, _loanAprBps * _loanPrincipalAmount
                ) < minimum.interest
            )
    ) || (_offerFee > 0) || (_offerEndTime < _loanEndTime) 
) {
    revert NotStrictlyImprovedError();
}
```

### Recommended Mitigation Steps

Add check to ensure the required minimum improvement when users refinance a loan. 

### Assessed type

Invalid Validation

**[0xend (Gondi) acknowledged and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/68#issuecomment-2067054065):**
> We should get rid of this one. This was left as legacy (only improving apr matters).

**[0xA5DF (judge) decreased severity to Low and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/68#issuecomment-2067659989):**
> Thanks, it indeed seems from the code that those checks were supposed to run, therefore this is a valid issue. However, regarding severity - I fail to see why this is a significant issue. How does this impact the borrower or other users?

**[0xend (Gondi) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/68#issuecomment-2067713984):**
> No impact on borrower/lender. 
>
> https://github.com/pixeldaogg/florida-contracts/pull/361 - changing.

***

## [[15] Owner cannot change the allocator address from `address(0)`](https://github.com/code-423n4/2024-04-gondi-findings/issues/62)

*Note: At the judge’s request [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/70#issuecomment-2067964983), this downgraded issue from the same warden has been included in this report for completeness.*

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L202

### Impact

The base interest allocator is set in the Pool through two steps: `setBaseInterestAllocator()` and `confirmBaseInterestAllocator()`. The `confirmBaseInterestAllocator()` function can be called by anyone.

This function executes the logic using the `_newBaseInterestAllocator` input from the caller, not the value set by the owner in `setBaseInterestAllocator()`. The check for `_newBaseInterestAllocator == getPendingBaseInterestAllocator` is only done when `cachedAllocator != address(0)`.

After all, the pending values are reset. `getPendingBaseInterestAllocator` is reset to `address(0)` and `getPendingBaseInterestAllocatorSetTime` is reset to `type(uint256).max`. An attacker could exploit this to prevent the owner from changing the allocator address from `address(0)`.

### Proof of Concept

```solidity
function confirmBaseInterestAllocator(address _newBaseInterestAllocator) external {
    address cachedAllocator = getBaseInterestAllocator;
    if (cachedAllocator != address(0)) { 
        if (getPendingBaseInterestAllocatorSetTime + UPDATE_WAITING_TIME > block.timestamp) {
            revert TooSoonError();
        }
        if (getPendingBaseInterestAllocator != _newBaseInterestAllocator) {
            revert InvalidInputError();
        }
        IBaseInterestAllocator(cachedAllocator).transferAll();
        asset.approve(cachedAllocator, 0);
    }
    asset.approve(_newBaseInterestAllocator, type(uint256).max);

    getBaseInterestAllocator = _newBaseInterestAllocator;
    getPendingBaseInterestAllocator = address(0);
    getPendingBaseInterestAllocatorSetTime = type(uint256).max;

    emit BaseInterestAllocatorSet(_newBaseInterestAllocator);
}
```

When the owner tries to change the allocator address from an `address(0)` allocator, they need to call `setBaseInterestAllocator()`. This function records the request in `getPendingBaseInterestAllocator` and `getPendingBaseInterestAllocatorSetTime`.

If the attacker immediately calls the `confirmBaseInterestAllocator()` function with `_newBaseInterestAllocator = address(0)`, the `getPendingBaseInterestAllocator` will reset, preventing the owner from ever setting a new base interest allocator.

### Recommended Mitigation Steps

Only allow owner to call `confirmBaseInterestAllocator()`.

### Assessed type

DoS

**[0xA5DF (judge) decreased severity to Low and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/62#issuecomment-2060467853):**
> > If the attacker immediately calls the `confirmBaseInterestAllocator()` function with `_newBaseInterestAllocator = address(0)`, the `getPendingBaseInterestAllocator` will reset, preventing the owner from ever setting a new base interest allocator.
> 
> If the attacker calls `confirmBaseInterestAllocator()` with the zero address then the owner can call this again with the right address. If the attacker calls this with anything else then the owner can call again `setBaseInterestAllocator()` and then `confirmBaseInterestAllocator()`.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-04-gondi-findings/issues/62#event-12543252830)**


## [[16] Attacker can set arbitrary allocator in case `cachedAllocator == address(0)`](https://github.com/code-423n4/2024-04-gondi-findings/issues/61)

*Note: At the judge’s request [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/70#issuecomment-2067964983), this downgraded issue from the same warden has been included in this report for completeness.*

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L204

### Impact

The base interest allocator is set in the Pool through two steps: `setBaseInterestAllocator()` and `confirmBaseInterestAllocator()`. The `confirmBaseInterestAllocator()` function allows anyone to call it.

This function will execute the logic using the `_newBaseInterestAllocator` input passed in by the caller, instead of the value set by the owner in `setBaseInterestAllocator()`. The verification for `_newBaseInterestAllocator == getPendingBaseInterestAllocator` is only performed when `cachedAllocator != address(0)`.

As a result, if `cachedAllocator == address(0)`, anyone can set an arbitrary address for the allocator. And since the asset is approved to the new allocator address, attacker could steal all the fund available in the Pool contract.

### Proof of Concept

```solidity
function confirmBaseInterestAllocator(address _newBaseInterestAllocator) external {
    address cachedAllocator = getBaseInterestAllocator;
    // @audit in case cachedAllocator = address(0), anyone can set arbitrary allocator 
    if (cachedAllocator != address(0)) { 
        if (getPendingBaseInterestAllocatorSetTime + UPDATE_WAITING_TIME > block.timestamp) {
            revert TooSoonError();
        }
        if (getPendingBaseInterestAllocator != _newBaseInterestAllocator) {
            revert InvalidInputError();
        }
        IBaseInterestAllocator(cachedAllocator).transferAll();
        asset.approve(cachedAllocator, 0);
    }
    asset.approve(_newBaseInterestAllocator, type(uint256).max);

    getBaseInterestAllocator = _newBaseInterestAllocator;
    getPendingBaseInterestAllocator = address(0);
    getPendingBaseInterestAllocatorSetTime = type(uint256).max;

    emit BaseInterestAllocatorSet(_newBaseInterestAllocator);
}
```

As we can see, the check if input `_newBaseInterestAllocator` matches the pending value is only performed when `cachedAllocator != address(0)`. The same applies to the `UPDATE_WAITING_TIME` check.

If the contract is deployed without an allocator set up, or whenever the owner sets the allocator address to `0`, an attacker could call `confirmBaseInterestAllocator()` to set it to an arbitrary address.

### Recommended Mitigation Steps

Consider running all the checks when `cachedAllocator == address(0)` as well.

### Assessed type

Invalid Validation

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/61#issuecomment-2060469818):**
> I have some doubts about severity, since this can happen only at the initial stage, and the owner can simply set this to the right address (owner would have to wait some time though). Leaving open for the sponsor to comment.

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/61#issuecomment-2067335348):**
> This is definitely an issue but as pointed out, a low one.

**[0xA5DF (judge) decreased severity to Low and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/61#issuecomment-2067666159):**
> Yeah, but when the allocator is changed, the approval is revoked for the old allocator. As this happens only at the initial stage then no funds are expected to be in the pool at this time.

***

## [[17] Possible overflow when borrower accepts renegotiation offer in `refinanceFull()`](https://github.com/code-423n4/2024-04-gondi-findings/issues/56)

*Note: At the judge’s request [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/70#issuecomment-2067964983), this downgraded issue from the same warden has been included in this report for completeness.*

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L195

### Impact

In the `refinanceFull()` function, if the borrower is the caller, it signifies a renegotiation offer. The borrower will clear the accrued interest, permitting them to repay the accrued interest without waiting for the full loan repayment. 

```solidity
} else {
    /// @notice Borrowers clears interest
    _checkSignature(_renegotiationOffer.lender, _renegotiationOffer.hash(), _renegotiationOfferSignature);
    netNewLender -= totalAccruedInterest; // @audit possible overflow when netNewLender < totalAccruedInterest
    totalAccruedInterest = 0;
}
```

However, if `netNewLender < totalAccruedInterest`, there's a risk of overflow. Consequently, `refinanceFull()` will revert, preventing the borrower from accepting the renegotiation offer.

### Proof of Concept

Consider the following scenario:

1. Alice (the borrower) takes a 10 ETH loan, and the accrued interest is already 2.1 ETH.
2. Alice wants to reduce the principal amount and is interested in a renegotiation offer from Bob for a 2 ETH principal amount loan.
3. When Alice calls `refinanceFull()` and passes in Bob's renegotiation offer, it reverts because:

```solidity
netNewLender = principalAmount - fee = 2 eth (assume fee = 0)
totalAccruedInterest = 2.1 eth
netNewLender -= totalAccruedInterest (revert)
```

### Recommended Mitigation Steps

Consider deducting only `min(netNewLender, totalAccruedInterest)` from `netNewLender`.

### Assessed type

Under/Overflow

**[0xend (Gondi) confirmed and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/56#issuecomment-2067080946):**
> Given the nature of loans, renegotiating a loan to a principal lower than interest accrues seems highly unlikely but would consider this. I think this is a low.

**[0xA5DF (judge) decreased severity to Low and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/56#issuecomment-2067669302):**
> @0xend - Marking as low due to this. If the warden can prove that this scenario is at least somewhat likely to happen I'd consider reinstating Medium severity.

## [[18] Function `settleWithBuyout()` incorrectly calculate the main lender because single lender can have multiple tranches in a loan](https://github.com/code-423n4/2024-04-gondi-findings/issues/55)

*Note: At the judge’s request [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/70#issuecomment-2067964983), this downgraded issue from the same warden has been included in this report for completeness.*

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionWithBuyoutLoanLiquidator.sol#L69

### Impact

The `settleWithBuyout()` function is used to settle an auction with a buyout from the main lender. It calculates the main lender by looping through all the tranches and selecting the lender of the largest tranche as the main lender.

```solidity
uint256 largestTrancheIdx;
uint256 largestPrincipal;
for (uint256 i = 0; i < _loan.tranche.length;) {
    if (_loan.tranche[i].principalAmount > largestPrincipal) {
        largestPrincipal = _loan.tranche[i].principalAmount;
        largestTrancheIdx = i;
    }
    unchecked {
        ++i;
    }
}
```

However, this is incorrect as a single lender could have multiple tranches. This could be abused by a borrower to manipulate the selection of the main lender.

### Proof of Concept

Consider the following scenario:

1. Alice (lender) offers to lend 40 eth.
2. Bob (another lender) offers to lend 20 eth.
3. Caleb (borrower) wants to allow Bob, not Alice, to buyout his NFT but still wants to borrow all 40 eth from Alice. He can take partial loan from Alice like this:

```solidity
tranche = [
  0: 20 eth from Bob
  1: 20 eth from Alice
  2: 0.01 eth from Caleb
  3: 20 eth from Alice
]
```

As you can see, even though Alice lend 40 eth to Caleb, Bob will be the main lender. And also since the tranche of Alice is not consecutive (Caleb intentionally put 0.01 eth in between), they cannot be merged as well.

### Recommended Mitigation Steps

To get the correct main lender, sum up the total principal in different tranches from the same lender.

**[0xend (Gondi) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/55#issuecomment-2067093038):**
> I think this is highly unlikely given tranches have seniority. Looks like I forgot to check for `_getMinTranchePrincipal` (will be addressed in the mitigation review) which would also set a cost for caleb.
> 
> I'd say this is definitely low risk. Lastly, lender could actually refinance the small tranche from the borrower and merge all tranches.

**[0xA5DF (judge) decreased severity to Low and commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/55#issuecomment-2067961567):**
> I think that selecting the lender with the biggest tranche rather than the biggest share is a reasonable design considering that finding the lender with the biggest share would be much more complicated and expensive to do on chain. And it isn't like the lender with the biggest share is losing their debt payment.
> 
> Regarding manipulation, as long as it happens at the beginning of the loan, far from the starting time of the auction, I don't think it's significant. Marking as Low.

**[0xA5DF (judge) commented](https://github.com/code-423n4/2024-04-gondi-findings/issues/70#issuecomment-2067964983):**
> | Risk | Title | Verdict |
> |:----:|:-----------:|---------|
> | 01 | No need to approve `_aavePool` to spend `_aToken` | R |
> | 02 | Open TODOs | R |
> | 03 | Function `burnAndWithdraw()` does not withdraw old ERC721s | L |
> | 04 | Function in `BytesLib` could revert with no error message | R |
> | 05 | `setProtocolFee()` can be called multiple times to spam event emission | R |
> | 06 | Repayment and liquidation could be blocked if token has a callhook to receiver | L |
> | 07 | Wrong event emission in `finalUpdateMultiSourceLoanAddress()` | L |
> | 08 | `addCallers()` does not check `_callers.length == pendingCallers.length` | L |
> | 09 | Partial refinance offer could be used in `refinanceFull()` | L |
> | 10 | Owner can set `_multiSourceLoan` to `address(0)` directly without `updateMultiSourceLoanAddressFirst()` | L |
> | 11 | Slippage of stETH swap could make `validateOffer()` revert | L |
> | 12 | Modifier `onlyReadyForWithdrawal` is repeatedly execute when users withdraw multiple tokens | R |
> | 13 | Should use defined variable in function `_checkValidators()` | NC |
> | 14 | Function `_checkStrictlyBetter()` does not check for `ImprovementMinimum` | L |
> | 15 | Owner cannot change the allocator address from `address(0)` | L |
> | 16 | Attacker can set arbitrary allocator in case `cachedAllocator == address(0)` | L |
> | 17 | Possible overflow when borrower accepts renegotiation offer in `refinanceFull()` | L |
> | 18 | Function `settleWithBuyout()` incorrectly calculate the main lender because single lender can have multiple tranches in a loan | L |

***

# Gas Optimizations

For this audit, 1 report was submitted by wardens detailing gas optimizations. The [report highlighted below](https://github.com/code-423n4/2024-04-gondi-findings/issues/79) by **erebus** received the top score from the judge.

## [G-01] Redundant calls to `vaultExists` modifier with the same `_vaultId`

There are two identical calls to the same modifier with the same arguments, which is redundant. Remove one of them ([see here](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/UserVault.sol#L219)):

```solidity
    /// @inheritdoc IUserVault
    /// @dev Read `depositERC721`.                               .---------------------.----------------------------- redundant
    function depositEth(uint256 _vaultId) external payable vaultExists(_vaultId) vaultExists(_vaultId) {
        _vaultERC20s[ETH][_vaultId] += msg.value;

        emit ERC20Deposited(_vaultId, ETH, msg.value);
    }
```

## [G-02] Cached `lidoData` not used

When reading the `aprBps` field of the `LidoData` struct, the fourth line reads from storage instead of the cached one. Consider using `lidoData` instead of `getLidoData`, which saves 1 `SLOAD` ([see here](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/LidoEthBaseInterestAllocator.sol#L77)).

```solidity
    /// @inheritdoc IBaseInterestAllocator
    function getBaseApr() external view override returns (uint256) {
        LidoData memory lidoData = getLidoData;
        uint256 aprBps = getLidoData.aprBps;
        if (block.timestamp - lidoData.lastTs > getLidoUpdateTolerance) {
            uint256 shareRate = _currentShareRate();
            aprBps = uint16(
                _BPS * _SECONDS_PER_YEAR * (shareRate - lidoData.shareRate) / lidoData.shareRate
                    / (block.timestamp - lidoData.lastTs) // @audit no me enteroadgahdhjadgadc
            );
        }
        if (aprBps == 0) {
            revert InvalidAprError();
        }
        return aprBps;
    }
```

## [G-03] Optimization when emitting `MultiSourceLoanUpdated`

As `_pendingMultiSourceLoanAddress` becomes `address(0)`, then there is no need to do an additional `SLOAD` in the event emission, just set it to `address(0)` ([see here](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/callbacks/PurchaseBundler.sol#L246)).

```solidity

    /// @inheritdoc IPurchaseBundler
    function finalUpdateMultiSourceLoanAddress(address _newAddress) external onlyOwner {
        if (_pendingMultiSourceLoanAddress != _newAddress) {
            revert InvalidAddressUpdateError();
        }

        _multiSourceLoan = MultiSourceLoan(_pendingMultiSourceLoanAddress);
        _pendingMultiSourceLoanAddress = address(0);

        emit MultiSourceLoanUpdated(_pendingMultiSourceLoanAddress);  // should be address(0)
    }
```

## [G-04] Redundant code

In `AuctionLoanLiquidator::placeBid`, the check for the increment of the highest bid is repeated as it is done already in the `_placeBidChecks` method. Consider removing the one within the function ([here](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L229C1-L232C10)):

```solidity
    /// @inheritdoc IAuctionLoanLiquidator
    function placeBid(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        external
        nonReentrant
        returns (Auction memory)
    {
        _placeBidChecks(_nftAddress, _tokenId, _auction, _bid);
         
        // @audit already done in _placeBidChecks
        uint256 currentHighestBid = _auction.highestBid;
        if (_bid == 0 || (currentHighestBid.mulDivDown(_BPS + MIN_INCREMENT_BPS, _BPS) >= _bid)) {
            revert MinBidError(_bid);
        }

        ...

    function _placeBidChecks(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        internal
        view
        virtual
    {
        _checkAuction(_nftAddress, _tokenId, _auction);
        if (_bid == 0 || (_auction.highestBid.mulDivDown(_BPS + MIN_INCREMENT_BPS, _BPS) >= _bid)) {
            revert MinBidError(_bid);
        }
    }
```

***

# Audit Analysis

For this audit, 2 analysis reports were submitted by wardens. An analysis report examines the codebase as a whole, providing observations and advice on such topics as architecture, mechanism, or approach. The [report highlighted below](https://github.com/code-423n4/2024-04-gondi-findings/issues/71) by **minhquanym** received the top score from the judge.

*The following warden also submitted a report: [oakcobalt](https://github.com/code-423n4/2024-04-gondi-findings/issues/83).*


## System Overview

### What is Gondi

Gondi is a decentralized non-custodial NFT lending protocol that offers the most flexible and capital efficient primitive. Gondi loans allows borrowers to access liquidity and obtain the best marginal rate when available as well as allow lenders to earn yield on their capital with the flexibility of entering and exiting their position any moment without affecting borrowers' loans.

In new version Gondi V3 loan offers are submitted from both protocol pools as well as peers market participants creating deep liquidity as well as precise risk pricing.

### Overview

The diagram below presented the interaction of Gondi contracts.

*Note: to view the provided image, please see the original submission [here](https://github.com/code-423n4/2024-04-gondi-findings/issues/71).*

The Gondi contracts can be divided into three sets:

**Loan**: This is the core of the Gondi protocol and includes the main logic for the Gondi P2P NFT lending protocol.
- **`BaseLoan`**: Manages basic loan offer and renegotiation offer information. Since the offer is signed off-chain, this contract contains the logic needed to cancel the offer on-chain.
- **`PurchaseBundler`**: Allows users to bundle a purchase and take out a loan in a single transaction. For example, if there's an NFT for sale at 20e and an outstanding loan offer for 10e, a user only needs 10e to start, instead of needing 20e to buy it first and then take out a loan for 10e.
- **`CallbackHandler`**: Whitelists and checks callback return data. This contract handles calls to `PurchaseBundler`.
- **`LiquidationHandler`**: Includes the function `_liquidateLoan()` to handle loan liquidation cases (one lender & multiple lenders).
- **`MultiSourceLoan`**: All the contracts mentioned above are composed into the MultiSourceLoan. This contract, which will be deployed, contains all the logic of these abstract contracts above.

**Pool**: Gondi Pools are simply ERC4626, allowing lenders to deposit liquidity. This Pool will act as the lender in the main MultiSourceLoan contract.
- **`PoolOfferHandler`**: Whitelists loan terms for different collections, durations, APRs, etc. For any given offer, it checks that the requested principal is below the max allowed, the APR is at least the minimum defined, and the max senior repayment is below the max allowed.
- **`WithdrawalQueue`**: Pools use `WithdrawalQueues` to manage fund withdrawals. Each withdrawal request is represented by an NFT (which can be traded, borrowed against, etc).
- **`FeeManager`**: A protocol fee contract, contains a function to calculate the fee when a loan is repaid or liquidated.
- **`AaveUsdcBaseInterestAllocator`**: When funds are not deployed to any loan, they could be deposited in third-party protocols to earn base interest. In the case of a USDC pool, it will be deposited in the Aave protocol.
- **`LidoEthBaseInterestAllocator`**: If the asset is WETH, it will be deposited in Lido to earn interest.

**Liquidator**: Contains the logic to handle liquidation when the borrower cannot meet the repayment deadline.
- **`AuctionLoanLiquidator`**: Implements core functionalities to run an auction for the NFT collateral. It receives an NFT to be auctioned when a loan defaults.
- **`AuctionWithBuyoutLoanLiquidator`**: Extends `AuctionLoanLiquidator` but adds a feature to allow the main lender to buyout the NFT. The main lender, defined as the lender with the largest tranche in the loan, will need to repay other lenders' principal plus interest to receive the NFT.
- **`LiquidationDistributor`**: Distributes the received funds after an auction is settled to lenders. Distributions follow a seniority-based waterfall system, covering the principal and accrued interest of the senior tranche before repaying the principal of the next tranche in seniority.

## Approach taken in evaluating the codebase

### Time spent: 8 days (Full duration of the audit)

**Day 1** 
- Reading the documentation provided in Gitbook.

**Days 2-3**
- Understanding and noting down the logical scope (which contracts will be deployed, which is inherited by other contracts).
- Review utils contracts, contracts with less logic and will be inherited by other contracts like `/utils`, `AddressManager`, `InputChecker`, `Multicall`, `UserVault`, etc.

**Days 4-5**
- Review core logic of `/loan` including `BaseLoan`, `MultiSourceLoan`, `CallbackHandler` and `PurchaseBundler`.

**Days 6-7**
- Review core logic of `/pools` including `Pool`, `PoolOfferHandler`, `WithdrawalQueue`.
- Review the interaction of `Pool` with `MultiSourceLoan` through `LoanManager`.

**Day 8**
- Writing reports.

## Architecture Recommendations

### Unique Features

- **Gondi Pool:** This feature allows anyone to access yield-bearing assets by simply depositing WETH or USDC into Gondi Pools. The core loan is P2P, so introducing a Pool enables users with less capital and time to participate in the protocol.
- **Multiple Tranches:** This feature allows one NFT to draw liquidity from multiple lender offers.

### Comparisons with Existing Patterns

- Gondi is similar to another P2P NFT lending protocol I've audited, Particle. Both protocols allow borrowers to take a loan using NFT as collateral and also enable refinancing of existing loans. However, Gondi is more complex, introducing additional features as described above.

## Centralization Risks

### Involved Actors and Their Roles

- The primary trust assumption in the contract is the owner role in all contracts. However, core parameters cannot be changed immediately and require the owner's approval.
- For all two-step parameter change processes, the contract will always use the input parameters of the caller in the "confirm" step to modify variables. Sometimes, only the owner can call these "confirm" functions, but at other times they are open to everyone. As shown in some H/M reports, there are issues with these functions.

## Resources used to gain deeper context on the codebase

- Official documentation [here](https://app.gitbook.com/o/4HJV0LcOOnJ7AVJ77p8e/s/W2WSJrV6PSLWo4p8vIGq/).
- Inline comments in codebase.
- Previous audit reports found [here](https://app.gitbook.com/o/4HJV0LcOOnJ7AVJ77p8e/s/W2WSJrV6PSLWo4p8vIGq/security-and-audits).

## Mechanism Review

### Permissionless Refinance & Renegotiation

- In Gondi, lenders can refinance any existing loans in the protocol in a permissionless manner. This means they can refinance any outstanding loan, without the borrower's action, by reducing the loan's APR by at least 5%. Refinancing can occur at any time while the loan is outstanding and not locked. However, refinancing is triggered only by the lender and doesn't require the borrower's acceptance.
- The `ImprovementMinimum` is a useful factor to protect against spamming issues. Without a minimum, attackers could spam refinance loans with only a `1 wei` increase in the principal token or increase the loan duration by one second, making it impossible for others to refinance.
- This mechanism creates a fair and open market for all lenders to offer the best liquidity terms to the borrower. However, it may be challenging for typical users to keep up with and use the protocol. Lenders must monitor their open loans regularly to ensure their loan is still active and their funds are being utilized.

### Liquidation Auction

- Defaulted loans with two or more tranches go through an auction process. The senior tranche lender has priority over more junior tranches. Distributions follow a waterfall from most senior first to most junior last. Distributions first cover the principal and accrued interest of the senior tranche before repaying the principal of the next tranche in seniority.
- The seniority of a tranche is simply its position in the `tranche` list in `Loan`. The protocol allows lenders to specify their preferred position when submitting a loan offer through the `maxSeniorRepayment` and `principalAmount`.

**Example**: `[-----amount from offer A--------, --------amount from offer B ---------,]`

Looking now at offer B:
- `maxSeniorRepayment` Maximum amount of `principal+max` interest (calculated as the apr at the duration of the loan) from other offers that can be placed ahead of offer B. In other words, `A < maxSeniorRepayment`.
- `principalAmount` Max amount of principal a loan can have up to offer B has been filled. In other words, `A+B < principalAmount`.

### Gondi Pool

- Gondi Pools are simply a ERC4626, lenders can deposit liquidity to this Pool and this Pool will be the lender in the main `MultiSourceLoan` contract.
- Gondi Pools are greatly beneficial for lenders who lack the required knowledge or time to actively manage their open loans.
- Some NFTs may have high values, so less capital lenders can also participate in the protocol through Gondi Pools.

## Systemic Risks/Architecture-Level Weak Spots and Their Mitigation Strategies

- **Missing Input Validation:** Some structures serve multiple purposes. For instance, `RenegotiationOffer` is used in `refinanceFull()`, `refinancePartial()`, and `addNewTranche()`. However, there's no validation implemented to ensure that the structure only contains the necessary data. Specifically, `refinanceFull()` doesn't check if the tranche list is empty. Generally, the protocol lacks sufficient input validation, leading to numerous high-risk issues.
- Another issue related to shared structures is that borrower/lender signatures for these structures will be identical. This occurs even if they intend to call only one function. Since the structure data is shared, the caller could use the signature to invoke other functions.
- The two-step process for changing certain parameters is inconsistent. Some functions are only owner-based, while others are permissionless. These functions typically use the input provided in the "confirm" call to update the state variables, but they don't always verify whether it matches the values in the "pending" call.

### Time spent

70 hours

***

# [Mitigation Review](#mitigation-review)

## Introduction

Following the C4 audit, 3 wardens ([bin2chen](https://code4rena.com/@bin2chen), [minhquanym](https://code4rena.com/@minhquanym) and [oakcobalt](https://code4rena.com/@oakcobalt)) reviewed the mitigations for all identified issues. Additional details can be found within the [C4 Gondi Mitigation Review repository](https://github.com/code-423n4/2024-05-gondi-mitigation).

## Overview of Changes

**[Summary from the Sponsor](https://github.com/code-423n4/2024-05-gondi-mitigation?tab=readme-ov-file#overview-of-changes):**

All invidivual fixes are addressed in a separate PR. The branche feature/developWithOpt contains the merge of all such features + a few that were found by other auditors. Because of contract size issues when adding all fixes, the following has changed:

- There's no bonus on Pool reallocation (we expect the dao to run this function and incur the cost).
- In `refinancePartial`, we don't allow extra principal (this is a corner case and can still be done with `addNewTranche`).
- Some of the two step variable changes in the Pool (`LoanManager`) have been moved to a helper contract. Feel free to ignore issues regarding the `PoolOfferHandler` since we are working on a different one given the limitations of the existing one.
- Please note the out-of-scope item [H-10](https://github.com/code-423n4/2024-04-gondi-findings/issues/35). While not in scope for awards, general commentary on its design is welcome. The [PR](https://github.com/pixeldaogg/florida-contracts/tree/fix/29) for H-12 can give some insight into it.

## Mitigation Review Scope

| Mitigation of | Purpose | 
| ------------- | ----------- |
| H-01 | Only tranche lender can call `mergeTranches` so it assumes the responsibility | 
| H-02 | Change order in multiplication/division as suggested| | 
| H-03 | Added caller check to avoid anyone calling `distribute` | 
| H-04 | Added `tokenIdCheck` | 
| H-05 | Change to `safeTransferFrom` buyer | 
| H-06 | Added loanLiquidation call | 
| H-07 | Clear state vars | 
| H-08 | Need to break 1 before | 
| H-09 | Missing `+` | 
| H-11 | Passing protocol fee | 
| H-12 | Added caller check | 
| H-13 | Added duration check | 
| H-14 | Added `nonReentrant` | 
| H-15 | Strict -> `<=` | 
| H-16 | `validateOffer` changed to view so validators cannot change state | 
| H-17 | Check `trancheIndex` to differentiate between `refiFull`/`addNewTranche` | 
| M-01 | Check total tranches + min amount per tranche | 
| M-02 | Checking signature from the existing borrower | 
| M-03 | `addNewTranche` uses `protocolFee` from struct | 
| M-04 | changed to reallocate (`currentBalance`, `principalAmount`, `true`) instead of proposed solution (same result) to be compliant with the interface | 
| M-05 | Added `collectFees` method | 
| M-06, M-07 | Terms must be passed in the confirm as well | 
| M-08 | Only adding a comment here. Borrower should always set `block.timestamp + small time delta` as expiration to control when the loan can be started | 
| M-09 | Missing collected fees in accounting | 
| M-10 | Check `loanContract` | 
| M-11 | There's a min bid now. This + the min improvement invalidates DoS | 
| M-12 | Limit auction extensions | 
| M-13 | Proactively reallocate (we got rid of the bonus though) | 
| M-14 | Corrected calculation of fees as suggested | 
| M-15 | Added check (`maxDuration` cannot be longer) | 
| M-16 | Changed to loan end time (instead of current timestamp) | 
| M-17 | Added field in hash | 
| M-18 | Always call `loanManager` (even if 0 proceeds) | 
| M-19 | Strict to `>=` | 
| M-20 | Set right value for `getLidoData` timestamp | 

## Out of Scope

H-10 - Refinacing a loan locks the loan. Adding a tranche can only be accepted by the borrower now. External actors can only front-run a limited number of times.

## Mitigation Review Summary

**The wardens confirmed the mitigations for all in-scope findings except for H-17 and M-12, which were unmitigated. They also surfaced several new issues, including 1 High severity and 4 Medium severity findings. The table below provides details regarding the status of each in-scope vulnerability from the original audit, followed by full details on the new issues and any in-scope vulnerabilities that were unmitigated.**

| Original Issue | Status | Full Details |
| ----------- | ------------- | ----------- |
| H-01 | 🟢 Mitigation Confirmed | Reports from [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/50) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/2) |
| H-02 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/42), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/51) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/3) |
| H-03 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/43), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/52) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/4) |
| H-04 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/44), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/53) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/5) |
| H-05 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/45), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/54) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/6) |
| H-06 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/46), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/55) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/7) |
| H-07 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/47), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/56) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/8) |
| H-08 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/48), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/57) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/9) |
| H-09 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/49), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/58) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/10) |
| H-11 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/89), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/59) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/12) |
| H-12 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/90), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/60) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/13) |
| H-13 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/91), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/61) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/14) |
| H-14 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/92), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/62) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/15) |
| H-15 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/93), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/63) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/16) |
| H-16 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/94), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/64) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/17) |
| H-17 | 🔴 Unmitigated | Reports from [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/65), [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/18) and [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/95) |
| M-01 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/96), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/66) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/19) |
| M-02 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/97), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/67) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/20) |
| M-03 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/98), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/68) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/21) |
| M-04 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/99), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/69) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/22) |
| M-05 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/100), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/70) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/23) |
| M-06 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/101), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/71) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/24) |
| M-07 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/102), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/72) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/25) |
| M-08 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/103) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/26) |
| M-09 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/104) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/74) |
| M-10 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/105), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/75) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/28) |
| M-11 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/106) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/76) |
| M-12 | 🔴 Unmitigated | Report from [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/30) |
| M-13 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/108) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/31) |
| M-14 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/109), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/79) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/32) |
| M-15 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/110), [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/33) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/80) |
| M-16 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/111), [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34) and [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/81) |
| M-17 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/112), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/82) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/35) |
| M-18 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/113), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/83) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/36) |
| M-19 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/114), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/84) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/37) |
| M-20 | 🟢 Mitigation Confirmed | Reports from [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/115), [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/85) and [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/38) |

***

## [H-17 Unmitigated](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/65)

*Submitted by [minhquanym]((https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/65)), also found by [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/18) and [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/95)*

`MultiSourceLoan.sol#L1172-L1188`

### Issue

The `refinanceFull()` and `addNewTranche()` functions share the same signature. This could lead to an issue where a user signs a signature for a full refinance, but it gets used in `addNewTranche()`. This could inadvertently increase the principal amount of the loan, which may not be the user's intention.

### Mitigation

The fix did differentiating between the two functions by using the length of `trancheIndex` and the value of `trancheIndex[0]`.

- `addNewTranche`: The length of the `trancheIndex` must be `1`, and its value is `_totalTranches`. This should result in an out-of-bound error if it's used in refinance.
- refinanceFull: The length of `trancheIndex` must be equal to `_totalTranches`.

With this check in place, I believe the `RenegotiationOffer` for a loan with 1 tranche can still be used for both functions. This is because `trancheIndex` isn't actually used in `refinanceFull`, but only in `refinancePartial`. So the out-of-bound exception will not be raised in `refinanceFull`.

```solidity
function _checkAddNewTrancheOffer(RenegotiationOffer calldata _renegotiationOffer, uint256 _totalTranches)
    private
    pure
{
    if (_renegotiationOffer.trancheIndex.length != 1 || _renegotiationOffer.trancheIndex[0] != _totalTranches) {
        revert InvalidRenegotiationOfferError();
    }
}

function _checkRefinanceFullRenegotiationOffer(
    RenegotiationOffer calldata _renegotiationOffer,
    uint256 _totalTranches
) private pure {
    if (_renegotiationOffer.trancheIndex.length != _totalTranches) {
        revert InvalidRenegotiationOfferError();
    }
}
```

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/65#issuecomment-2143437603):**
> The Warden describes a case under which exhibit H-17 is not mitigated; specifically, a loan with a single tranche can have a signature generated that will pass both validation functions without raising an error. I believe that the observation is correct as the scenario of a single-tranche loan is valid. 
> 
> The impact is not the same as the original H-17 exhibit as we are describing a signature **intended for creating new tranches** being reused for refinancing (instead of the other way around), it still represents a case of H-17 not alleviated.

*** 

## [M-12 Unmitigated](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/30)

*Submitted by [bin2chen]((https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/30))*

`LiquidationHandler.sol#L72`

### Vulnerability details

The PR adds `getMaxExtension` to address the issue of auction times being indefinitely postponed. The maximum time is: `block.timestamp + _liquidationAuctionDuration + getMaxExtension`. However, `_liquidationAuctionDuration` can be modified, with the current constraint being `_liquidationAuctionDuration < MAX_AUCTION_DURATION (7 days)`.

```solidity
    function updateLiquidationAuctionDuration(uint48 _newDuration) external override onlyOwner {
@>      if (_newDuration < MIN_AUCTION_DURATION || _newDuration > MAX_AUCTION_DURATION) {
            revert InvalidDurationError();
        }
        _liquidationAuctionDuration = _newDuration;

        emit LiquidationAuctionDurationUpdated(_newDuration);
    }
```

Therefore, it's still possible that: `block.timestamp + _liquidationAuctionDuration + getMaxExtension` could exceed `7 Days`.

### Recommended Mitigation

It is recommended to restrict `_liquidationAuctionDuration + ILoanLiquidator(liquidator).getMaxExtension < MAX_AUCTION_DURATION`.

```diff
    function updateLiquidationAuctionDuration(uint48 _newDuration) external override onlyOwner {
-       if (_newDuration < MIN_AUCTION_DURATION || _newDuration > MAX_AUCTION_DURATION) {
+       if (_newDuration < MIN_AUCTION_DURATION || _newDuration + ILoanLiquidator(liquidator).getMaxExtension  > MAX_AUCTION_DURATION) {    
            revert InvalidDurationError();
        }
        _liquidationAuctionDuration = _newDuration;

        emit LiquidationAuctionDurationUpdated(_newDuration);
    }
```

### Assessed type

Context

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/30#issuecomment-2143438558):**
> The Warden specifies that M-12 has not been sufficiently mitigated as the vulnerability can still resurface after a reconfiguration of the contract due to inadequate limitations in the `LiquidationHandler::updateLiquidationAuctionDuration` function. I consider the rationale sufficiently elaborated and confirm that M-12 remains unmitigated as it can resurface via future reconfigurations of the system that should be prohibited by the code itself.

***

## [`refinanceFromLoanExecutionData()` Reusing borrower's signature to steal funds](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/39)

*Submitted by [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/39)*

**Severity: High**

`MultiSourceLoan.sol#L320`

### Vulnerability details

In `refinanceFromLoanExecutionData()`, the `LoanExecutionData` signature of `borrower` is reusable (since there are no nonces, as long as it doesn't expire).

Suppose `loanOffer.fee =100`. Then, each time `refinanceFromLoanExecutionData()` is executed the funds flow as follows:
1. Lender pay = `loanOffer.principalAmount - loanOffer.fee`
2. Borrower repay = `loanOffer.principalAmount`

So for each execution, `lender` receives a `loanOffer.fee` difference (`loanOffer.principalAmount` - (`loanOffer.principalAmount - loanOffer.fee`)).

This way a malicious `lender` can monitor `emitLoan()` to reuse the signature of the `borrower` to steal funds. Example below:
1. Bob signs a borrower's `LoanExecutionData` and executes `emitLoan()`. loan: {fee = 1% , lender = Alice}.
2. Malicious user Alice executes `refinanceFromLoanExecutionData(loan)` after Bob's transaction, using the signature that Bob just signed.
3. Every time `refinanceFromLoanExecutionData(loan)` is executed, Alice gets an extra `fee = 1%`.

### POC

The following code demonstrates the reuse of the `emitLoan()` signature to steal funds.

Add to MultiSourceLoan.t.sol:

```solidity
    function testReuseBorrowSign() public {
        uint256 privateKey = 100;
        address otherBorrower = vm.addr(privateKey);
        uint256 otherToken = collateralTokenId + 1;

        IMultiSourceLoan.LoanOffer memory loanOffer =
            _getSampleOffer(address(collateralCollection), otherToken, _INITIAL_PRINCIPAL);
        //@info capacity can't 0
        loanOffer.capacity = 1000000e18;
        //@info need fees 1 %
        loanOffer.fee = _INITIAL_PRINCIPAL / 100;         
        testToken.mint(loanOffer.lender, _INITIAL_PRINCIPAL * 10000);
        testToken.mint(otherBorrower, _INITIAL_PRINCIPAL * 10000);
        vm.prank(otherBorrower);
        testToken.approve(address(_msLoan), type(uint256).max);

        collateralCollection.mint(otherBorrower, otherToken);
        vm.prank(otherBorrower);
        collateralCollection.approve(address(_msLoan), otherToken);
        loanOffer.nftCollateralTokenId = otherToken;

        loanOffer.duration = 30 days;
        IMultiSourceLoan.LoanExecutionData memory lde = _sampleLoanExecutionData(loanOffer);
        lde.executionData.tokenId = otherToken;
        lde.borrower = otherBorrower;
        bytes32 executionDataHash = _msLoan.DOMAIN_SEPARATOR().toTypedDataHash(lde.executionData.hash());
        (uint8 vOffer, bytes32 rOffer, bytes32 sOffer) = vm.sign(privateKey, executionDataHash);
        lde.borrowerOfferSignature = abi.encodePacked(rOffer, sOffer, vOffer);
        //@info first loan
        (uint256 loanId, IMultiSourceLoan.Loan memory loan) = _msLoan.emitLoan(lde);

        //@info ********* reuse sign *********
        uint256 initBalance = testToken.balanceOf(loanOffer.lender);
        for(uint i = 0; i < 10; i++) {
            (loanId, loan) =
                _msLoan.refinanceFromLoanExecutionData(loanId, loan, lde);  
            console.log("lender balance increased:", testToken.balanceOf(loanOffer.lender) - initBalance);
               
        }
        //@info ********* reuse sign end *********
    }    
```

```console
$ forge test -vvv --match-test testReuseBorrowSign

[PASS] testReuseBorrowSign() (gas: 952628)
Logs:
  lender balance increased: 1000000
  lender balance increased: 2000000
  lender balance increased: 3000000
  lender balance increased: 4000000
  lender balance increased: 5000000
  lender balance increased: 6000000
  lender balance increased: 7000000
  lender balance increased: 8000000
  lender balance increased: 9000000
  lender balance increased: 10000000
```

### Impact

Reusing `LoanExecutionData` signature to steal funds.

### Recommended Mitigation

Recommend that all signatures in the protocol require `nonces` (requires major changes); or, `refinanceFromLoanExecutionData()` can only be executed by `borrower` itself.

### Assessed type

Context

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/39#event-12934156676)**

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/39#issuecomment-2143437390):**
> The Warden demonstrates a significant signature re-use vulnerability that will permit a fee to be consecutively re-executed to increase the fee a lender acquires from their borrower. A high risk rating is appropriate for this vulnerability given that funds are directly affected.

***

## [`getLoanManager.updateOfferHandler()` should be executed inside `confirmOfferHandler()`](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/33)

*Submitted by [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/33), also found by [minhquanym](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/86)*

**Severity: Medium**

`LoanManagerParameterSetter.sol#L70`

### Vulnerability details

The PR adds that the new `__offerHandler.getMaxDuration` can't be larger than the old one, and already avoids the problem of `getMinTimeBetweenWithdrawalQueues` being too large. Also added using `LoanManagerParameterSetter.sol` to set `offerHandler`.

In two steps:
1. `setOfferHandler()` => set `ProposedOfferHandler = new offerHandler`.
2. After the `UPDATE_WAITING_TIME` time expires, execute `confirmOfferHandler()` to make the `ProposedOfferHandler` effective.

But currently it works immediately, not after `UPDATE_WAITING_TIME`.

```solidity
    function setOfferHandler(address __offerHandler) external onlyOwner {
        __offerHandler.checkNotZero();

        if (IPoolOfferHandler(__offerHandler).getMaxDuration() > IPoolOfferHandler(getOfferHandler).getMaxDuration()) {
            revert InvalidInputError();
        }

        getProposedOfferHandler = __offerHandler;
        getProposedOfferHandlerSetTime = block.timestamp;
@>      ILoanManager(getLoanManager).updateOfferHandler(__offerHandler); //@audit call in  confirmOfferHandler()

        emit ProposedOfferHandlerSet(__offerHandler);
    }

    /// @notice Confirm the OfferHandler contract.
    /// @param __offerHandler The new OfferHandler address.
    function confirmOfferHandler(address __offerHandler) external onlyOwner {
        if (getProposedOfferHandlerSetTime + UPDATE_WAITING_TIME > block.timestamp) {
            revert TooSoonError();
        }
        if (getProposedOfferHandler != __offerHandler) {
            revert InvalidInputError();
        }

        getOfferHandler = __offerHandler;
        getProposedOfferHandler = address(0);
        getProposedOfferHandlerSetTime = type(uint256).max;

        emit OfferHandlerSet(__offerHandler);
    }
```

### Recommended Mitigation

```diff
    function setOfferHandler(address __offerHandler) external onlyOwner {
        __offerHandler.checkNotZero();

        if (IPoolOfferHandler(__offerHandler).getMaxDuration() > IPoolOfferHandler(getOfferHandler).getMaxDuration()) {
            revert InvalidInputError();
        }

        getProposedOfferHandler = __offerHandler;
        getProposedOfferHandlerSetTime = block.timestamp;
-       ILoanManager(getLoanManager).updateOfferHandler(__offerHandler);

        emit ProposedOfferHandlerSet(__offerHandler);
    }

    /// @notice Confirm the OfferHandler contract.
    /// @param __offerHandler The new OfferHandler address.
    function confirmOfferHandler(address __offerHandler) external onlyOwner {
        if (getProposedOfferHandlerSetTime + UPDATE_WAITING_TIME > block.timestamp) {
            revert TooSoonError();
        }
        if (getProposedOfferHandler != __offerHandler) {
            revert InvalidInputError();
        }
        getOfferHandler = __offerHandler;
        getProposedOfferHandler = address(0);
        getProposedOfferHandlerSetTime = type(uint256).max;
+       ILoanManager(getLoanManager).updateOfferHandler(__offerHandler);

        emit OfferHandlerSet(__offerHandler);
    }
```

### Assessed type

Context

**[0xend (Gondi) confirmed via duplicate Issue #86](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/86#event-12934152748)**

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/33#issuecomment-2143438721):**
> The Warden highlights how the revised offer handler update mechanism will fail to enforce the two-step process properly, and will immediately update the offer handler. I consider a medium risk rating to be appropriate for this submission, but it does not relate to the M-15 mitigation as that was carried out properly and its atomic change does not introduce this issue.

***

## [`AuctionWithBuyoutLoanLiquidator` lender get less interest](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34)

*Submitted by [bin2chen](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34)*

**Severity: Medium**

`AuctionWithBuyoutLoanLiquidator.sol#L100`

`LiquidationDistributor.sol#L60`

### Vulnerability details

The PR changed to loan end time instead of current timestamp. In order to resolve the issue of liquidation,`LiquidationDistributor.distribute()` may break `maxSeniorRepayment`'s expectations.

There are two issues:

**First Issue:** The PR Also modified another contract `AuctionWithBuyoutLoanLiquidator.sol`:

```diff
contract AuctionWithBuyoutLoanLiquidator is AuctionLoanLiquidator {
...

+       uint256 loanEndTime = _loan.startTime + _loan.duration;
        uint256 totalOwed;
        for (uint256 i; i < _loan.tranche.length;) {
            if (i != largestTrancheIdx) {
                IMultiSourceLoan.Tranche calldata thisTranche = _loan.tranche[i];
                uint256 owed = thisTranche.principalAmount + thisTranche.accruedInterest
-                   + thisTranche.principalAmount.getInterest(thisTranche.aprBps, block.timestamp - thisTranche.startTime);
+                   + thisTranche.principalAmount.getInterest(thisTranche.aprBps, loanEndTime - thisTranche.startTime);
                totalOwed += owed;
                asset.safeTransferFrom(msg.sender, thisTranche.lender, owed);

                if (getLoanManagerRegistry.isLoanManager(thisTranche.lender)) {
                    LoanManager(thisTranche.lender).loanLiquidation(
                        thisTranche.loanId,
                        thisTranche.principalAmount,
                        thisTranche.aprBps,
                        thisTranche.accruedInterest,
                        _loan.protocolFee,
                        owed,
                        thisTranche.startTime
                    );
                }
            }
```

The change to `AuctionWithBuyoutLoanLiquidator` does not make sense; the interest should still be calculated using the current time, because:

1. `AuctionWithBuyoutLoanLiquidator` is a user-initiated repayment and requires full payment of the amount owed, unlike a bidding auction where there is a shortfall in the amount owed. So there is no `maxSeniorRepayment` problem. 
2. The user has 4 days to consider `MAX_TIME_FOR_MAIN_LENDER_TO_BUY = 4 days`. During this time, `lender` has not received the payment, and should calculate the interest. Users can maliciously delay the repayment, anyway, when to repay, the repayment amount is the same.

**Second Issue:** `LiquidationDistributor` should only use `loan end time` if the reimbursement amount is insufficient. It makes more sense to use `block.timestamp` when the amount is enough. Since each `Tranche` has different `aprBps`, it would make more sense to calculate the interest at the `current time` and allocate the excess amount in proportion to the last `owed` amount `excess = _proceeds - _totalOwed;`.

### Impact

The "lender" is missing 4 days of interest. The purchaser can postpone the purchase without loss.

### Recommended Mitigation

`AuctionWithBuyoutLoanLiquidator.sol` still using `block.timestamp`. `LiquidationDistributor.sol` - repayment is first made on the basis of `loan end time` and if there are funds remaining. The percentage of arrears is calculated on the basis of `block.timestamp' and the excess is distributed proportionately.

### Assessed type

Context

**[0xend (gondi) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34#issuecomment-2131583748):**
> Agree on keeping block.timestamp in `AuctionWithBuyoutLoanLiquidator.sol`
> 
> I think the complexity (gas consumption) of having to use one or the other (endtime / block.timestamp) does not justify it. Ultimately, this is weighing more favorably tranches that were started earlier but the absolute delta here is quite small (and if that's not the case, because someone started a tranche with only a few seconds to go let's say, then whoever that was had full context on the risk of a liquidation/subsequent distribution).

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34#issuecomment-2143438919):**
> The Warden has applied economic criticism to the revised loan buy-out mechanism by the main lender, specifying that interest accrual is missing during the window in which a main lender can buy out a loan. 
> 
> I believe the criticism levied is valid and a medium risk rating is appropriate as expected lender profits are slashed without a valid safety or incentive argument.
>
> However, this submission does not constitute a denial of the M-16 alleviation as the commit that alleviates is the following which does not include the `AuctionWithBuyoutLoanLiquidator` change. As such, this submission is considered a new finding.

**[0xend (gondi) acknowledged](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/34#event-13267897653)**

***

## [Loan offer's required collateral `tokenId` is not validated in some conditions, borrower can use any NFT to initiate loans](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/119)

*Submitted by [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/119)*

**Severity: Medium**

`MultiSourceLoan.sol#L850`

### Proof of concept

When a lender generates `LoanOffer`, they can either specify a specific NFT `tokenId`, or allow a collection offer (any `tokenId` within the NFT collection). `LoanOffer` and `executionData`'s collateral Id match is checked in `_checkValidators()`.

Based on code doc, a lender's `LoanOffer` struct -> the collateral tokenId required:
1. Empty validator array input -> lender want the exact `tokenId` match;
2. Single validator element input `&& _loanOffer.validators[0].validator == address(0)` -> lender accepts any token in the collection;
3. Non-empty validator array `&&_loanOffer.validators[0].validator != address(0)` -> lender wants offer validators to check the offer.

```solidity
|>  /// @notice Check generic offer validators for a given offer or
    ///         an exact match if no validators are given. The validators
    ///         check is performed only if tokenId is set to 0.
    ///         Having one empty validator is used for collection offers (all IDs match).
...
    function _checkValidators(LoanOffer calldata _loanOffer, uint256 _tokenId) private view {
...
```

Edge case: A lender wants an exact tokenId match and the `tokenId` is 0. 

Based on the code doc, an exact match check should be performed when no validators are given. So lender's LoanOffer will be: `(1) _loanOffer.nftCollateralTokenId =0` ; `(2) _loanOffer.validators.length == 0;`

However, `_checkValidators()` will not check this `loanOffer` at all. Due to an empty validator array is provided, exact `tokenId` match is not checked due to vulnerable check `if (_loanOffer.nftCollateralTokenId != 0){...`. In the else branch, for-loop will be directly skipped, and exit the function with no checks.

```solidity
    function _checkValidators(LoanOffer calldata _loanOffer, uint256 _tokenId) private view {
       uint256 offerTokenId = _loanOffer.nftCollateralTokenId;
        //@audit This is vulnerable check condition, will cause tokenId=0 and empty validators to be skipped entirely
 |>     if (_loanOffer.nftCollateralTokenId != 0) {
            if (offerTokenId != _tokenId) {
                revert InvalidCollateralIdError();
            }
        } else {
            uint256 totalValidators = _loanOffer.validators.length;
            if (totalValidators == 0 && _tokenId != 0) {
                revert InvalidCollateralIdError();
            } else if ((totalValidators == 1) && _isZeroAddress(_loanOffer.validators[0].validator)) {
                return;
            }
            for (uint256 i = 0; i < totalValidators;) {
                IBaseLoan.OfferValidator memory thisValidator = _loanOffer.validators[i];
                IOfferValidator(thisValidator.validator).validateOffer(_loanOffer, _tokenId, thisValidator.arguments);
                unchecked {
                    ++i;
                }
            }
        }
    }
```

`emitLoan() →_processOffersFromExecutionData() → validateOfferExecution()→ _checkValidators()`

As a result, a borrower can use any collateral `tokenId` when the lender requires `tokenId` 0.

### Recommendation

Refactor the if control flow in `_checkValidators()` to always check `tokenId` for exact match if empty validator array.

**[0xend (Gondi) disputed and commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/119#issuecomment-2131508835):**
> Not sure I follow. If `loanOffer.nftCollateralTokenId = 0` and there are not validators, then we check if (`totalValidators == 0 && _tokenId != 0`) which would revert if the `tokenId` of the actual loan is any other than 0?

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/119#issuecomment-2143435954):**
> The Warden has demonstrated a limitation of the system when dealing with token IDs of `0` which are valid per the EIP-721 standard. I believe this is a valid issue with the codebase, and I advise the Sponsor to revisit it as the condition they mention would not revert given that `_tokenId` would be **deliberately `0` to match a token ID of `0`**.
> 
> I believe a medium risk assessment is fair, as there is no documented limitation of the system's ability to support Token IDs of `0` and any orders involving them would be incorrectly validated and effectively not be fulfilled properly.

***

## [Auction proceeds might be distributed to an incorrect queue, due to incorrect loan contract passed to `_loanTermination()`](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/120)

*Submitted by [oakcobalt](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/120)*

**Severity: Medium**

`Pool.sol#L423`

### Impact

Auction proceeds might be distributed to an incorrect queue, due to incorrect loan contract used in `_loanTermination()`.

### Proof of concept

Whenever a loan is closed (repaid or liquidation auction settlements) the correct loan contract (`MultiSourceLoan` address) where the loan is initiated needs to be passed to `Pool::_loanTermination` to determine the queue where the payment belongs.

In `_loanTermination()`, `getLastLoanId[idx][_loanContract]` will be used to determine the correct queue.

```solidity
//src/lib/pools/Pool.sol
    function _loanTermination(
|>      address _loanContract,
        uint256 _loanId,
        uint256 _principalAmount,
        uint256 _apr,
        uint256 _interestEarned,
        uint256 _received
    ) private {
...
        for (i = 1; i < totalQueues;) {
            idx = (pendingIndex + i) % totalQueues;
|>          if (getLastLoanId[idx][_loanContract] >= _loanId) {
                break;
            }
```

The problem is when a loan is terminated in the auction settlement `flow. _loanContract` can be incorrect. `LiquidationDistributor::distribute()` will call `LoanManager(_tranche.lender).loanLiquidation()` and `loanLiquidation()` will pass `msg.sender` which is `LiquidationDistributor` address as `_loanContract` to `_loanTermination()`. 

If `LiquidationDistributor` is not intended to be a loan contract, `getLastLoanId[idx][_loanContract]` will always return 0. The payment will always go to the pool instead of the correct queue.

```solidity
    function loanLiquidation(
        uint256 _loanId,
        uint256 _principalAmount,
        uint256 _apr,
        uint256,
        uint256 _protocolFee,
        uint256 _received,
        uint256 _startTime
    ) external override {
...
         //@audit msg.sender is LiquidationDistributor, not a loan contract
 |>       _loanTermination(msg.sender, _loanId, _principalAmount, netApr, interestEarned, _received - fees);
```

### Recommendation

1. In `LiquidationDistributor::distribute()` and `pool::loanLiquidation()` need to pass `_auction.loanAddress` to be used in `_loanTermination()`, this will return the correct queue index.
2. Or always ensure that LiquidationDistributor.sol is added as a `loanContract`.

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/120#issuecomment-2143435787):**
> The Warden claims that a loan liquidation will pass in the wrong loan contract address; however, the `Pool::_loanTermination` function will function as expected even if the `_loanContract` passed in is not a contract. This is further confirmed by the test suites of the system, inferring that this is the expected method of operation for the `LiquidationDistributor` contract specifically as it is never added as a loan contract. I advise the Sponsor to evaluate this submission and confirm my assumptions that the described issue is not a vulnerability but rather an expected project mechanism.

**[oakcobalt (warden) commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/120#issuecomment-2144017837):**
> Please see test file [here](https://gist.github.com/flowercrimson/c7dca997e767e1a60b4776245423d97d).
> 
> Added unit test `testLoanLiquidationDistributionQueue()`, which checks that auction payment is accounted entirely to the pool instead of the correct queue.
> 
> Replace the test file in the mitigation repo with the gist file and run `forge test --match-contract LiquidationDistributorTest --match-test testLoanLiquidationDistributionQueue`
> ```solidity
> //test/LiquidationDistributor.t.sol
> ...
>  //test auction proceeds goes entirely to the pool instead of the correct queue.
>     function testLoanLiquidationDistributionQueue() public {
>         //Step1: Queue 0:  borrower took loan1
>         _deposit(_principal * 2);
>         (, IMultiSourceLoan.Loan memory loan) = _getInitialLoanWithPoolLender(
>             _borrower,
>             collateralTokenId
>         );
>         //Step2: Queue 1: minTime passed, new queue deployed
>         uint256 tokens = 1;
>         uint256 minTime = _pool.getMinTimeBetweenWithdrawalQueues();
> 
>         vm.prank(_user);
>         _pool.withdraw(tokens, _user, _user);
>         vm.warp(minTime + 1);
>         _pool.deployWithdrawalQueue();
> 
>         //Step3: Queue 1: loan1 expired and liquidated by AuctionLoanLiquidator. Skip implementation here.
>         //Step4: Queue 1: borrower took loan2
>         BaseAprUpdate();
>         collateralCollection.mint(_borrower, 2);
>         vm.prank(_borrower);
>         collateralCollection.approve(address(_msLoan), 2);
>         _getInitialLoanWithPoolLender(_borrower, 2);
>         //Step5: Queue 1: loan1 auction settled, proceeds distributed to pool contract. Suppose proceeds = _principal.
>         uint256 repayment = _principal;
>         _asset.mint(liquidator, repayment);
>         vm.startPrank(liquidator);
>        _asset.approve(address(_distributor), repayment);
>         _distributor.distribute(repayment, loan);
>         vm.stopPrank();
>         //check none of the deployed queues received any proceeds, proceeds are all accounted towards the pool as undeployed assets
>         assertEq(_pool.getTotalReceived(0), 0);
>         assertEq(_pool.getTotalReceived(1), 0);
>         assertEq(_pool.getUndeployedAssets(), repayment);
>     }
> ```
> ```
> Ran 1 test for test/LiquidationDistributor.t.sol:LiquidationDistributorTest
> [PASS] testLoanLiquidationDistributionQueue() (gas: 2196896)
> Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 8.81ms (1.04ms CPU time)
> ```

**[0xsomeone (judge) increased severity to Medium and commented](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/120#issuecomment-2144756022):**
> After discussing with both the original Gondi judge and evaluating the PoC myself, I have concluded that the misbehavior described by the Warden does exist and should not be considered a QA flaw. 
>
> In detail, lending pool proceeds from liquidations will not be reflected in withdrawals within the pending queues, and will instead be considered undeployed capital of the pool and thus be "owned" by all non-withdrawing (i.e. active) shareholders of the pool. This is incorrect behavior as the pending withdrawal queue of the system is meant to accommodate for loan liquidations that occurred for loans created before a queue's creation, and thus warrants an M risk rating as funds were not lost but rather misattributed.

**[0xend (Gondi) confirmed](https://github.com/code-423n4/2024-05-gondi-mitigation-findings/issues/120#event-13267639725)**

***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
