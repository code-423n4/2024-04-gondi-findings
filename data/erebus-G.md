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