# Summary

| Risk | Title |
| --- | --- |
| L-1 | No need to approve `__aavePool` to spend `__aToken` | 
| L-2 | Open TODOs |
| L-3 | Function `burnAndWithdraw()` does not withdraw old ERC721s |
| L-4 | Function in BytesLib could revert with no error message |
| L-5 | `setProtocolFee()` can be called multiple times to spam event emission |
| L-6 | Repayment and liquidation could be blocked if token has a callhook to receiver |
| L-7 | Wrong event emission in `finalUpdateMultiSourceLoanAddress()` |
| L-8 | `addCallers()` does not check `_callers.length == pendingCallers.length` |
| L-9 | Race condition when `block.timestamp == expirationTime` |
| L-10 | Partial refinance offer could be used in `refinanceFull()` |
| L-11 | Owner can set `_multiSourceLoan` to address(0) directly without `updateMultiSourceLoanAddressFirst()` |
| L-12 | Slippage of stETH swap could make `validateOffer()` revert |
| N-1 | Modifier `onlyReadyForWithdrawal` is repeatedly execute when users withdraw multiple tokens |
| N-2 | Should use defined variable in function `_checkValidators()` | 


# L-1. No need to approve `__aavePool` to spend `__aToken`

[AaveUsdcBaseInterestAllocator.sol#L44](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/AaveUsdcBaseInterestAllocator.sol#L44)

## Detail
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
Check out the AavePool code here https://polygonscan.com/address/0x1ed647b250e5b6d71dc7b25806f44c33f5658f71#code#F1#L196

---

# L-2. Open TODOs

[AaveUsdcBaseInterestAllocator#L90](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/AaveUsdcBaseInterestAllocator.sol#L90), 
[AaveUsdcBaseInterestAllocator.sol#L16](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/AaveUsdcBaseInterestAllocator.sol#L16)

[AuctionWithBuyoutLoanLiquidator.sol#L61](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionWithBuyoutLoanLiquidator.sol#L61)

[LoanManager.sol#L10](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L10)

[ValidatorHelpers.sol#L4](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/ValidatorHelpers.sol#L4)


## Detail
There are a lot of open TODOs in the codebase. They indicate there are some missing functionalities needed to be implemented. For example

```solidity
function claimRewards() external {
    /// TODO: getIncentivesController
}
```

---

# L-3. Function `burnAndWithdraw()` does not withdraw old ERC721s

[UserVault.sol#L125](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/UserVault.sol#L125)

## Details
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

---

# L-4. Function in BytesLib could revert with no error message 

[BytesLib.sol](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/BytesLib.sol)

## Details
All functions in `BytesLib` have some require check for overflow. However, these checks will only work with Solidity version < 0.8 because Solidity 0.8 already has some overflow check. For example, in the function `slice()`, in case overflow actually happens in the first check, the calculation `_length + 31` is already revert by solidity 0.8 before checking the condition in the require.
```solidity
function slice(bytes memory _bytes, uint256 _start, uint256 _length) internal pure returns (bytes memory) {
    require(_length + 31 >= _length, "slice_overflow");
    require(_start + _length >= _start, "slice_overflow"); // @audit These calculation will revert with solidity 0.8
    require(_bytes.length >= _start + _length, "slice_outOfBounds");
    ...
}
```

---

# L-5. `setProtocolFee()` can be called multiple times to spam event emission

https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/utils/WithProtocolFee.sol#L73

## Details
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

---

# L-6. Repayment and liquidation could be blocked if token has a callhook to receiver

[AuctionLoanLiquidator.sol#L285](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L285)

[LiquidationDistributor.sol#L88](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/LiquidationDistributor.sol#L88)

[MultiSourceLoan.sol#L946](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L946)

## Details
Some tokens like ERC777 has a callhook on receiver address. If these tokens are used in a loan, it could allow attacker to force liquidation/repayment to fail. For example, the function `settleAuction()` transfer the fee to originator. The originator could be an contract that will revert when receiving token transfer, making it impossible for auction to settle.
```solidity
asset.safeTransfer(_auction.originator, triggerFee); // @audit can revert if the token has callhook on receiver
asset.safeTransfer(msg.sender, triggerFee);
```

---

# L-7. Wrong event emission in `finalUpdateMultiSourceLoanAddress()`

[PurchaseBundler.sol#L238-L247](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/callbacks/PurchaseBundler.sol#L238-L247)

## Details
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

---

# L-8. `addCallers()` does not check `_callers.length == pendingCallers.length`

[LoanManager.sol#L80](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/LoanManager.sol#L80)

## Details
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

---

# L-9. Race condition when `block.timestamp == expirationTime`

[LiquidationHandler.sol#L91-L93](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/LiquidationHandler.sol#L91-L93)

```solidity
if (expirationTime > block.timestamp) { // @audit at expirationTime, loan can still be interacted
    revert LoanNotDueError(expirationTime);
}
```

[MultiSourceLoan.sol#L649-L651](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L649-L651)

```solidity
// @audit can liquidate when block.timestamp == endTime as well, user could be the largest tranche and buyout in 1 TX
if (_loan.startTime + _loan.duration < block.timestamp) { 
    revert LoanExpiredError();
}
```

As shown, when `block.timestamp == expirationTime`, the loan could be liquidated but it is still be able to be interacted (refinance, renegotiation, repay, add more tranches, ...).

One of the possible impact is that if one user want to buyout the NFT, he can be the largest tranche (main lender) and buyout through auction. Both actions can be finished in 1 transaction.

---

# L-10. Partial refinance offer could be used in `refinanceFull()`

[MultiSourceLoan.sol#L162-L169](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L162-L169)

# Details

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

---

# L-11. Owner can set `_multiSourceLoan` to address(0) directly without `updateMultiSourceLoanAddressFirst()`

[PurchaseBundler.sol#L238-L247](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/callbacks/PurchaseBundler.sol#L238-L247)

## Details
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

---

# L-12. Slippage of stETH swap could make `validateOffer()` revert

[Pool.sol#L407-L413](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/Pool.sol#L407-L413)

## Details
The MultiSourceLoan contract calls the `validateOffer()` function to verify that the loan term has been approved by the Pool contract. This function also draws the necessary capital from the base interest allocator to ensure a sufficient balance for the loan.

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

---

# N-1. Modifier `onlyReadyForWithdrawal` is repeatedly execute when users withdraw multiple tokens

[UserVault.sol#L80-L85](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/UserVault.sol#L80-L85)

## Detail
```solidity
modifier onlyReadyForWithdrawal(uint256 _vaultId) { // @audit Repeatedly checked when withdraw multiple tokens
    if (_readyForWithdrawal[_vaultId] != msg.sender) {
        revert NotApprovedError(_vaultId);
    }
    _;
}
```

The `onlyReadyForWithdrawal` modifier is used to check if the vault can be withdrawn and the permitted caller is call it. However, this check is performed in internal function, making it repeatedly call for the same `_vaultId` when users withdraw more than 1 tokens

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

---

# N-2. Should use defined variable in function `_checkValidators()`

[MultiSourceLoan.sol#L899-L901](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/loans/MultiSourceLoan.sol#L899-L901)

```solidity
function _checkValidators(LoanOffer calldata _loanOffer, uint256 _tokenId) private {
    uint256 offerTokenId = _loanOffer.nftCollateralTokenId;
    // @audit Should use the cache value above
    if (_loanOffer.nftCollateralTokenId != 0) {
```

---