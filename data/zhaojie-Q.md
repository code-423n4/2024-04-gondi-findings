
## [L1] mergeTranches and refinancePartial do not have nonReentrant modifiers

The `nonReentrant` modifier is added to most of the public functions in the `MultiSourceLoan` contract, but not to the `mergeTranches` and `refinancePartial` functions.
In some functions where the nonReentrant modifier has been added, it is still possible to call the `mergeTranches/refinancePartial` function for a reentrant attack if the callback function can be found.

## [L2] WithdrawalQueue#mint returns the id of the next token

The tokenId returned by the mint function does not correspond to the actual mint tokenId, and the caller needs -1 to get the correct id:

```solidity
    function mint(address _to, uint256 _shares) external returns (uint256) {
        if (msg.sender != getPool) {
            revert PoolOnlyCallableError();
        }
        _mint(_to, getNextTokenId);
        getShares[getNextTokenId] = _shares;
        getTotalShares += _shares;

        emit WithdrawalPositionMinted(getNextTokenId, _to, _shares);
        return getNextTokenId++;
    }

```

## [L3] Pool#withdraw lacks return value and the caller has no way of knowing which `WithdrawalQueue` his funds are in.

The withdraw function in Pool returns share and calls WithdrawalQueue.mint

```solidity
    WithdrawalQueue(_deployedQueues[_pendingQueueIndex].contractAddress).mint(receiver, shares);
```

However, the withdraw function does not return mint's tokenId, and the caller has no way of knowing his tokenId or which WithdrawalQueue his funds are in.