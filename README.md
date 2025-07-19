# compare-receipts

## Setup

```
python -m venv venv
source venv/bin/activate
pip install web3 rlp eth-utils trie
```

## Usage:
```
python compare_receipts.py \
    --rpc https://bsc-testnet-dataseed.bnbchain.org \
    --block 0x207f564
```

```
python3 print_cumulative_gas.py \    
    --rpc https://bsc-testnet-dataseed.bnbchain.org \
    --block 35547779
```