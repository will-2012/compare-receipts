#!/usr/bin/env python3
"""
Compare locally captured raw (RLP) transaction receipts to authoritative receipts
fetched from a BNB Smart Chain *Testnet* RPC endpoint, and verify the receipts trie
root against the block header's `receiptsRoot`.

Usage:
    python compare_receipts_bsc_testnet.py \
        --rpc https://bsc-testnet-dataseed.bnbchain.org \
        --block 0x207f564

You can pass the block in decimal (e.g., 34076004) or hex (0x207f564).

--------------------------------------------------------------------------
*** PASTING YOUR RAW RECEIPTS ***
--------------------------------------------------------------------------
Paste *exactly* what you copied (array syntax, commas, newlines — doesn't matter)
into the RAW_RECEIPTS_PASTE triple-quoted string below. The script will parse
all substrings that match the regex pattern `0x[0-9a-fA-F]+` *in order* and build
`RAW_RECEIPTS_HEX` automatically.

That way you don't need to hand-wrap 10 very long Python strings, and you avoid
copy/paste truncation bugs. If you later re-capture receipts, just replace the
paste block and rerun.

--------------------------------------------------------------------------
What the script does:
 1. Parse your pasted raw receipts -> list of hex strings (in given order).
 2. Connect to the RPC, fetch the block, and pull every transaction receipt.
 3. Canonical-encode RPC JSON receipts back into raw receipt bytes (with type prefix).
 4. Byte-compare (local vs RPC) by transaction index.
 5. Build two receipts tries (local, RPC) and compute their roots.
 6. Compare both to the header.receiptsRoot.

If there is a mismatch, the script prints a short field-level diff (type/status/
CGU/log-count) to help you pinpoint where the encoding diverges.

Dependencies:
    pip install web3 rlp eth-utils py-trie

--------------------------------------------------------------------------
"""

import argparse
import sys
import json
import re
from typing import List, Dict, Any

from web3 import Web3
import rlp
from eth_utils import keccak, to_checksum_address
from trie import HexaryTrie
from web3.middleware import ExtraDataToPOAMiddleware

# -------------------------------------------------------------------------
# 1. RAW RECEIPTS PASTE BLOCK (FROM YOUR COPY/PASTE)
# -------------------------------------------------------------------------
# NOTE: I inserted the *exact* payload you provided in chat on 2025-07-17.
# If you paste a new one, just replace everything between the triple quotes.
#
# IMPORTANT: Keep this as a *raw* triple-quoted string. Do NOT add Python
# escaping; just paste. The parser below will extract the 0x... tokens.
# -------------------------------------------------------------------------
RAW_RECEIPTS_PASTE = r"""[0xf9034501830301c0b9010000000000000400000000000000000000000000000000000000000000400000008000000000000000000000000000000000000000000000000000000000000000000000010000000000000008000000000000000000001000000000000000020000000000010000000000000000002000000000000000000000020010000000001000000000000000000000a00000000010000000400010200000040000000000000000000000002000000000000000000000400000000000000040000000000000000002000000008000000000000000000000400000000020000000000000000800000000000000000000000000000000000000000000000104000000001000f9023af89b94c776e808236b186c3fe8f18f7fd43949b6d5722bf863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000e6d3e46fb59cc5c66cffa8d31112bbd8966455dca0000000000000000000000000e4090f5f31c1cdc5367682ecc44d7997901c607da00000000000000000000000000000000000000000000000000106e69ba1610000f8dd94e4090f5f31c1cdc5367682ecc44d7997901c607df884a0e751baae971614714a5055ecbc0892f68c0e2d70c56550cb65a76bc840fa5f6ea0000000000000000000000000153b124d59d3a624c3c6de3b1280a1bf7e1dbcb7a0000000000000000000000000e6d3e46fb59cc5c66cffa8d31112bbd8966455dca0000000000000000000000000c776e808236b186c3fe8f18f7fd43949b6d5722bb8400000000000000000000000000000000000000000000000000106e69ba16100000000000000000000000000000000000000000000000000000106e69ba1610000f8bc94153b124d59d3a624c3c6de3b1280a1bf7e1dbcb7f884a04f7857497e115bb4e8acd8d9f7382eb4c159d874838d6368099523ab6ef9f631a0000000000000000000000000e6d3e46fb59cc5c66cffa8d31112bbd8966455dca0000000000000000000000000e6d3e46fb59cc5c66cffa8d31112bbd8966455dca0000000000000000000000000c776e808236b186c3fe8f18f7fd43949b6d5722ba00000000000000000000000000000000000000000000000000106e69ba1610000, 0xf901090183041bd9b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0, 0x02f9010901830495b8b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0, 0xf90324018306a818b9010000000000000400400000000000000000000000000000002000000000000040000000000000400000000000000000000000000000000000000000000000008000000001000000040040000008000000000000000000001000000000000000000000000000000000000000000000000000000000000000000008000010400000000000000000000080000000000000000000000000400010001000000080000000000000000000400000000000000000020000400000000000000200000000000000000002000000000000000000000000000000400000000000000000000010000000000000000000000000000000000000010000000000008000000000000000f90219f89b94f81d78e2ea9066ae008b8559c062b958df2104bef863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000163ff9b6397c3d33329d8d8d753f43f90502dc18a000000000000000000000000083e5d2a4a4729489126045ae8a5a5d3112d4f494a000000000000000000000000000000000000000000000000009ddfabba34d8000f8dd94163ff9b6397c3d33329d8d8d753f43f90502dc18f884a0fbde797d201c681b91056529119e0b02407c7bb96a4a2c75c01fc9667232c8dba0000000000000000000000000153b124d59d3a624c3c6de3b1280a1bf7e1dbcb7a000000000000000000000000083e5d2a4a4729489126045ae8a5a5d3112d4f494a0000000000000000000000000f81d78e2ea9066ae008b8559c062b958df2104beb84000000000000000000000000000000000000000000000000009ddfabba34d800000000000000000000000000000000000000000000000000009ddfabba34d8000f89b94153b124d59d3a624c3c6de3b1280a1bf7e1dbcb7f863a09b1bfa7fa9ee420a16e124f794c35ac9f90472acc99140eb2f6447c714cad8eba000000000000000000000000083e5d2a4a4729489126045ae8a5a5d3112d4f494a0000000000000000000000000f81d78e2ea9066ae008b8559c062b958df2104bea000000000000000000000000000000000000000000000000009ddfabba34d8000, 0x02f901a70183077110b9010000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000048001000000000400000000000000000000000000000000000000000000000000010000100000800000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000f89df89b945dd5a987569d00026c7cd2abdcaf93306950fa5ef863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000f68139f92fd4b5abd800795f6b02bf400554faaca000000000000000000000000011e2cae0cb5a125ca696defdcbd2fbe01dccafeea0000000000000000000000000000000000000000000000000016345785d8a0000, 0x02f90109808307cc56b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0, 0xf901090183081e5eb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0, 0xf901090183087066b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0, 0xf901860183087652b901000000000000000000000000400000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000104000000000000000000000000000000000000000010000000000000000000000000000000000f87cf87a940000000000000000000000000000000000001002f842a06c98249d85d88c3753a04a22230f595e4dc8d3dc86c34af35deeeedc861b89dba0000000000000000000000000a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0a0000000000000000000000000000000000000000000000000000128771ef802a0, 0xf901e001830903e2b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000002010000000000000000000000000000000000020000200000000000000000000080000000000000000000000000000000000000020000000000000000000000000000400000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000002000000000000000000000000010000000000000000000000000000000000000000000000f8d6f858940000000000000000000000000000000000001000e1a0627059660ea01c4733a328effb2294d2f86905bf806da763a89cee254de8bee5a00000000000000000000000000000000000000000000000000001bcb2ae7403f0f87a940000000000000000000000000000000000001000f842a093a090ecc682c002995fad3c85b30c5651d7fd29b0be5da9d784a3302aedc055a0000000000000000000000000a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0a0000000000000000000000000000000000000000000000000000fa24822142370]"""


# -------------------------------------------------------------------------
# 2. PARSE RAW_RECEIPTS_PASTE -> RAW_RECEIPTS_HEX (ORDER PRESERVED)
# -------------------------------------------------------------------------
RAW_RECEIPTS_HEX: List[str] = [m.group(0) for m in re.finditer(r"0x[0-9a-fA-F]+", RAW_RECEIPTS_PASTE)]


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------
def _strip0x(h: str) -> str:
    return h[2:] if h.startswith(("0x", "0X")) else h

def _hex_to_bytes(h: str) -> bytes:
    # Handle both string and bytes inputs
    if isinstance(h, bytes):
        h = h.hex()
    h = _strip0x(h)
    if len(h) % 2:
        # pad leading 0 if odd length (shouldn't happen but be robust)
        h = "0" + h
    return bytes.fromhex(h)


def decode_raw_receipt(raw_hex: str) -> Dict[str, Any]:
    """Decode a raw receipt (legacy or typed)."""
    b = _hex_to_bytes(raw_hex)
    if not b:
        raise ValueError("empty receipt")
    if b[0] in (0x01, 0x02, 0x03):
        rtype = b[0]
        payload = b[1:]
    else:
        rtype = 0
        payload = b

    items = rlp.decode(payload)
    if len(items) != 4:
        raise ValueError(f"unexpected receipt tuple len={len(items)}")

    status_or_root, cum_gas, bloom, logs_rlp = items
    status = int.from_bytes(status_or_root, "big") if status_or_root else 0
    cgas = int.from_bytes(cum_gas, "big") if cum_gas else 0

    logs = []
    for log_item in logs_rlp:
        addr_b, topics_rlp, data_b = log_item
        addr = to_checksum_address("0x" + addr_b.hex().rjust(40, "0"))
        topics = ["0x" + t.hex().rjust(64, "0") for t in topics_rlp]
        logs.append({"address": addr, "topics": topics, "data": "0x" + data_b.hex()})

    return {
        "type": rtype,
        "status": status,
        "cumulativeGasUsed": cgas,
        "logsBloom": bloom,
        "logs": logs,
    }


def encode_receipt_to_raw(rdict: Dict[str, Any]) -> bytes:
    """Encode a JSON-RPC style receipt dict back into canonical raw bytes."""
    status = rdict.get("status")
    if isinstance(status, str):
        status = int(status, 16)
    cum = rdict.get("cumulativeGasUsed")
    if isinstance(cum, str):
        cum = int(cum, 16)
    bloom_hex = rdict.get("logsBloom")
    bloom_bytes = _hex_to_bytes(bloom_hex) if isinstance(bloom_hex, str) else bloom_hex

    logs_obj = []
    for l in rdict.get("logs", []):
        addr_b = _hex_to_bytes(l["address"])
        topics_b = [_hex_to_bytes(t) for t in l["topics"]]
        data_b = _hex_to_bytes(l["data"])
        logs_obj.append([addr_b, topics_b, data_b])

    payload = rlp.encode([status, cum, bloom_bytes, logs_obj])
    rtype = rdict.get("type")
    if isinstance(rtype, str):
        rtype = int(rtype, 16)
    if rtype and rtype != 0:
        return bytes([rtype]) + payload
    return payload


def derive_receipts_root(raw_receipt_bytes_list: List[bytes]) -> str:
    """Build the receipts trie and return the Keccak root as 0x-hex."""
    t = HexaryTrie(db={})
    for i, raw in enumerate(raw_receipt_bytes_list):
        key = rlp.encode(i)
        t.set(key, raw)
    return "0x" + t.root_hash.hex()


# -------------------------------------------------------------------------
# CLI + main logic
# -------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Compare local raw receipts with RPC receipts & verify receiptsRoot")
    ap.add_argument("--rpc", required=True, help="HTTP RPC endpoint")
    ap.add_argument("--block", required=True, help="Block number (hex like 0x207f564 or decimal)")
    ap.add_argument("--show-local", action="store_true", help="Print parsed local receipt hex strings and lengths")
    ap.add_argument("--die-on-count-mismatch", action="store_true", help="Exit if local count != RPC tx count")
    args = ap.parse_args()

    # Normalize block param
    if args.block.startswith("0x"):
        block_num = int(args.block, 16)
        block_tag = args.block
    else:
        block_num = int(args.block)
        block_tag = hex(block_num)

    # Parse local receipts
    local_hex = RAW_RECEIPTS_HEX
    print(f"Parsed {len(local_hex)} local raw receipt(s) from paste block.")
    if args.show_local:
        for i, h in enumerate(local_hex):
            print(f"  idx {i:02d} len={len(_strip0x(h))//2}B {h[:20]}...")

    # Convert to bytes
    local_bytes = []
    for i, h in enumerate(local_hex):
        try:
            local_bytes.append(_hex_to_bytes(h))
        except Exception as e:
            print(f"ERROR decoding local receipt idx {i}: {e}")
            sys.exit(1)

    # Connect RPC
    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        sys.exit(f"ERROR: Cannot connect to RPC {args.rpc}")
    
    # Inject geth_poa_middleware
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    # Fetch block (full txs => we get tx types)
    try:
        block = w3.eth.get_block(block_num, full_transactions=True)
    except Exception as e:
        sys.exit(f"ERROR fetching block {block_tag} from RPC: {e}")

    txs = block["transactions"]
    print(f"Block {block_tag} from RPC: {len(txs)} tx(s); header.receiptsRoot={block['receiptsRoot']}")
    if len(local_hex) != len(txs):
        msg = (f"WARNING: local receipt count ({len(local_hex)}) != RPC tx count ({len(txs)}). "
               f"{'Exiting.' if args.die_on_count_mismatch else 'Continuing anyway.'}")
        print(msg)
        if args.die_on_count_mismatch:
            sys.exit(1)

    # Fetch RPC receipts
    rpc_receipts_json = []
    for tx in txs:
        r = w3.eth.get_transaction_receipt(tx["hash"])
        # Guarantee type field exists (fallback to tx.type)
        if "type" not in r or r["type"] is None:
            r["type"] = tx.get("type", "0x0")
        rpc_receipts_json.append(r)

    # Encode RPC receipts to raw bytes
    rpc_receipt_bytes = [encode_receipt_to_raw(r) for r in rpc_receipts_json]

    # Per-tx compare (truncate to min len if counts differ)
    cmp_len = min(len(local_bytes), len(rpc_receipt_bytes))
    print("\nPer-tx byte comparison:")
    for i in range(cmp_len):
        loc = local_bytes[i]
        rpcb = rpc_receipt_bytes[i]
        tx = txs[i]
        eq = loc == rpcb
        status = "OK" if eq else "MISMATCH"
        print(f"  idx {i:02d} hash={tx['hash'].hex()} -> {status} (local {len(loc)}B, rpc {len(rpcb)}B)")
        if not eq:
            # field-level decode diff
            try:
                d_loc = decode_raw_receipt(local_hex[i])
            except Exception as e:
                d_loc = {"err": str(e)}
            try:
                d_rpc = decode_raw_receipt("0x" + rpcb.hex())
            except Exception as e:
                d_rpc = {"err": str(e)}
            print(f"    local type/status/cgas/logs = {d_loc.get('type')} / {d_loc.get('status')} / {d_loc.get('cumulativeGasUsed')} / {len(d_loc.get('logs', [])) if 'logs' in d_loc else 'err'}")
            print(f"    rpc   type/status/cgas/logs = {d_rpc.get('type')} / {d_rpc.get('status')} / {d_rpc.get('cumulativeGasUsed')} / {len(d_rpc.get('logs', [])) if 'logs' in d_rpc else 'err'}")

    # Derive roots
    local_root = derive_receipts_root(local_bytes)
    rpc_root   = derive_receipts_root(rpc_receipt_bytes)
    header_root = block['receiptsRoot']

    print("\nReceipts root comparison:")
    print(f"  header : {header_root}")
    print(f"  local  : {local_root}")
    print(f"  rpc    : {rpc_root}")
    print(f"  header==local? {header_root.lower() == local_root.lower()}")
    print(f"  header==rpc?   {header_root.lower() == rpc_root.lower()}")
    print(f"  local==rpc?    {local_root.lower() == rpc_root.lower()}")


if __name__ == "__main__":
    main()
