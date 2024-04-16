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

