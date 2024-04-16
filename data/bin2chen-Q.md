## Findings Summary

| Label | Description |
| - | - |
| [L-01](#) |  Pool is typical ERC4626, vulnerable to inflation attacks|
| [L-02](#) | updateLiquidationContract() may break Ongoing bids |
| [L-03](#) | transferAll() will interact with a large number of assets, should not ignore slippage protection|
| [L-04](#) | `AuctionWithBuyoutLoanLiquidator._placeBidChecks()` check expiration should use block.timestamp <= timeLimit |
## [L-01] Pool is typical ERC4626, vulnerable to inflation attacks
`Pool.sol` is ERC4626
and has two features that make it vulnerable to inflationary attacks
1. `asset` can be donated to the contract, thus increasing the `exchangeRate`.
2. a portion of the `shares` is not initialized during construction and is locked in the contract.

The above two features can easily cause the first depositor to maliciously raise the exchangeRate to achieve the classic inflation attack.

Suggestion: add a fixed `mint(1e5)` of `shares` to be locked in the contract at initialization time.


## [L-02] updateLiquidationContract() may break Ongoing bids
`updateLiquidationContract()` modifies `_loanLiquidator`.
If the old `_loanLiquidator` already has active bids, calling `MultiSourceLoan.loanLiquidated()` when the bidding is over will not have the permissions to
and it won't be able to liquidate properly.
```solidity
@> function loanLiquidated(uint256 _loanId, Loan calldata _loan) external override onlyLiquidator {
        if (_loan.hash() ! = _loans[_loanId]) {
            revert InvalidLoanError(_loanId);
        }

        emit LoanLiquidated(_loanId);

        /// @dev Reclaim space.
        delete _loans[_loanId];
    }
```

Recommendation. 
`onlyLiquidator` needs to be compatible with the old `_loanLiquidator`.




## [L-03] transferAll() will interact with a large number of assets, should not ignore slippage protection
Currently `transferAll()` will exchange assets, and setting `force=true` means ignoring slippage protection
```solidity
 function transferAll() external {
      uint256 total = ERC20(_lido).balanceOf(address(this));
       _exchangeAndSendWeth(_onlyPool(), total, true);

        emit AllTransferred(total);
 }
```

This is insecure and vulnerable to sandwich attacks

Enabling slippage protection ``force=false`` is recommended
```diff
 function transferAll() external {
       uint256 total = ERC20(_lido).balanceOf(address(this));
-      _exchangeAndSendWeth(_onlyPool(), total, true);
+      _exchangeAndSendWeth(_onlyPool(), total, false);

        emit AllTransferred(total);
 }
```



## [L-04] `AuctionWithBuyoutLoanLiquidator._placeBidChecks()` check expiration should use block.timestamp <= timeLimit
`_placeBidChecks()` check expiration use `timeLimit > block.timestamp`
```solidity
    function _placeBidChecks(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        internal
        view
        override
    {
        super._placeBidChecks(_nftAddress, _tokenId, _auction, _bid);
        uint256 timeLimit = _auction.startTime + _timeForMainLenderToBuy;
@>      if (timeLimit > block.timestamp) {
            revert OptionToBuyStilValidError(timeLimit);
        }
    }
```
`settleWithBuyout()` use `timeLimit < block.timestamp`
```solidity
    function settleWithBuyout(
        address _nftAddress,
        uint256 _tokenId,
        Auction calldata _auction,
        IMultiSourceLoan.Loan calldata _loan
    ) external nonReentrant {
        /// TODO: Originator fee
        _checkAuction(_nftAddress, _tokenId, _auction);
        uint256 timeLimit = _auction.startTime + _timeForMainLenderToBuy;
@>      if (timeLimit < block.timestamp) {
            revert OptionToBuyExpiredError(timeLimit);
        }
```

This way if `block.timestamp == _auction.startTime + _timeForMainLenderToBuy` 
Both methods can be executed
suggest: 
```diff
    function _placeBidChecks(address _nftAddress, uint256 _tokenId, Auction memory _auction, uint256 _bid)
        internal
        view
        override
    {
        super._placeBidChecks(_nftAddress, _tokenId, _auction, _bid);
        uint256 timeLimit = _auction.startTime + _timeForMainLenderToBuy;
-       if (timeLimit > block.timestamp) {
+       if (timeLimit >= block.timestamp) {
            revert OptionToBuyStilValidError(timeLimit);
        }
    }
```