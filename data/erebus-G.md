# [G-01] Redundant calls to `vaultExists` modifier with the same `_vaultId`

There are two identical calls to the same modifier with the same arguments, which is redundant. Remove one of them ([link](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/UserVault.sol#L219)):

```solidity
    /// @inheritdoc IUserVault
    /// @dev Read `depositERC721`.                               .---------------------.----------------------------- redundant
    function depositEth(uint256 _vaultId) external payable vaultExists(_vaultId) vaultExists(_vaultId) {
        _vaultERC20s[ETH][_vaultId] += msg.value;

        emit ERC20Deposited(_vaultId, ETH, msg.value);
    }
```

# [G-02] Cached `lidoData` not used

When reading the `aprBps` field of the `LidoData` struct, the fourth line reads from storage instead of the cached one. Consider using `lidoData` instead of `getLidoData`, which saves 1 `SLOAD` ([link](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/pools/LidoEthBaseInterestAllocator.sol#L77))

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

# [G-03] Optimization when emitting `MultiSourceLoanUpdated`

As `_pendingMultiSourceLoanAddress` becomes `address(0)`, then there is no need to do an additional `SLOAD` in the event emission, just set it to `address(0)` ([link](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/callbacks/PurchaseBundler.sol#L246))

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

# [G-04] Redundant code

In `AuctionLoanLiquidator::placeBid`, the check for the increment of the highest bid is repeated as it is done already in the `_placeBidChecks` method. Consider removing the one within the function ([link](https://github.com/code-423n4/2024-04-gondi/blob/b9863d73c08fcdd2337dc80a8b5e0917e18b036c/src/lib/AuctionLoanLiquidator.sol#L229C1-L232C10)):

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