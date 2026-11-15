#!/usr/bin/env python3
"""Snapshot Hyperliquid mainnet market names for the approval page.

Usage: bundle-hyperliquid-markets.py META_JSON SPOT_META_JSON > OUT_JSON
Inputs are the mainnet /info responses for {"type":"meta"} and
{"type":"spotMeta"}. Perp asset IDs are universe positions; delisted perps
keep their slot. Spot asset IDs are 10000 + the pair's index.
"""
import json
import sys

meta = json.load(open(sys.argv[1]))
spot = json.load(open(sys.argv[2]))
tokens = {token["index"]: token["name"] for token in spot["tokens"]}
pairs = {}
for pair in spot["universe"]:
    base, quote = (tokens[i] for i in pair["tokens"])
    pairs[str(10000 + pair["index"])] = [base, quote]
json.dump({
    "perps": [asset["name"] for asset in meta["universe"]],
    "spot": pairs,
}, sys.stdout, separators=(",", ":"), sort_keys=True)
print()
