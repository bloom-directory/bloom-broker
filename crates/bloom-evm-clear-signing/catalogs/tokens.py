#!/usr/bin/env python3
"""Regenerate tokens.json from curated token lists, checked on chain.

A curated list proposes a token and its labels; the chain checks it. A token
is kept only if its address has code and its own decimals() agrees with the
list. A curated list's symbol and name are written, else the chain's; either
is skipped if it carries characters a label may not. A proxy
(EIP-1967 or the ZeppelinOS slot Circle uses) is marked upgradeable.

    python3 -I tokens.py > tokens.json      # exclusions go to stderr
"""

import json
import sys
import time
import urllib.error
import urllib.request

UNISWAP = "https://cdn.jsdelivr.net/npm/@uniswap/default-token-list@{}/build/uniswap-default.tokenlist.json"
UNISWAP_VERSION = "22.27.0"
# Uniswap's list has no Gnosis tokens.
GNOSIS = "https://tokens.coingecko.com/xdai/all.json"
RPC = {
    1: "https://ethereum-rpc.publicnode.com",
    10: "https://optimism-rpc.publicnode.com",
    100: "https://gnosis-rpc.publicnode.com",
    137: "https://polygon-bor-rpc.publicnode.com",
    8453: "https://base-rpc.publicnode.com",
    42161: "https://arbitrum-one-rpc.publicnode.com",
}
PROXY_SLOTS = [
    # EIP-1967 implementation
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    # ZeppelinOS implementation (Circle FiatToken)
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
]
DECIMALS, SYMBOL, NAME = "0x313ce567", "0x95d89b41", "0x06fdde03"
BATCH = 20


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "bloom-tokens"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def rpc(chain, calls):
    body = json.dumps(
        [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]
    ).encode()
    request = urllib.request.Request(
        RPC[chain], body, {"Content-Type": "application/json", "User-Agent": "bloom-tokens"}
    )
    for attempt in range(8):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                replies = {reply["id"]: reply.get("result") for reply in json.load(response)}
            return [replies.get(i) for i in range(len(calls))]
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 7:
                raise
            time.sleep(2**attempt)


def text(result):
    """An ABI string, or a bytes32 string as older tokens (MKR) return."""
    data = bytes.fromhex((result or "0x")[2:])
    if len(data) >= 64 and int.from_bytes(data[:32], "big") == 32:
        length = int.from_bytes(data[32:64], "big")
        data = data[64 : 64 + length]
    else:
        data = data[:32].rstrip(b"\0")
    return data.decode("utf-8", "replace")


def safe_symbol(symbol):
    return 0 < len(symbol.encode()) <= 16 and all(
        33 <= ord(c) < 127 and c not in "<>" for c in symbol
    )


def safe_name(name):
    return 0 < len(name) <= 64 and len(name.encode()) <= 256 and all(
        c.isprintable() and c not in "​‌‍⁠﻿­" for c in name
    )


def candidates():
    """Tokens with whether their list's labels are curated (Uniswap's are;
    CoinGecko's call wrapped xDAI "XDAI")."""
    seen = set()
    lists = [(get(UNISWAP.format(UNISWAP_VERSION))["tokens"], True), (get(GNOSIS)["tokens"], False)]
    for tokens, curated in lists:
        for token in tokens:
            key = (token["chainId"], token["address"].lower())
            if token["chainId"] in RPC and key not in seen:
                seen.add(key)
                yield {**token, "curated": curated}


def main():
    kept, excluded = [], []
    by_chain = {}
    for token in candidates():
        by_chain.setdefault(token["chainId"], []).append(token)
    for chain, tokens in sorted(by_chain.items()):
        for start in range(0, len(tokens), BATCH):
            batch = tokens[start : start + BATCH]
            calls = []
            for token in batch:
                address = token["address"].lower()
                calls.append(("eth_getCode", [address, "latest"]))
                for selector in (DECIMALS, SYMBOL, NAME):
                    calls.append(("eth_call", [{"to": address, "data": selector}, "latest"]))
                for slot in PROXY_SLOTS:
                    calls.append(("eth_getStorageAt", [address, slot, "latest"]))
            results = rpc(chain, calls)
            width = 4 + len(PROXY_SLOTS)
            for index, token in enumerate(batch):
                code, decimals, symbol, name, *slots = results[index * width : (index + 1) * width]
                address = token["address"].lower()
                reason = None
                if not code or code == "0x":
                    reason = "no code"
                elif not decimals or len(decimals) != 66:
                    reason = "no decimals()"
                else:
                    decimals = int(decimals, 16)
                    # The list's labels tell bridged USDC.e from native USDC, which
                    # both call themselves USDC; the chain's are the fallback.
                    symbols = (token["symbol"], text(symbol))
                    names = (token["name"], text(name))
                    if not token["curated"]:
                        symbols, names = symbols[::-1], names[::-1]
                    symbol = next((s for s in symbols if safe_symbol(s)), None)
                    name = next((n for n in names if safe_name(n)), None)
                    if decimals != token["decimals"] or decimals > 255:
                        reason = f"decimals {decimals} != list {token['decimals']}"
                    elif symbol is None or name is None:
                        reason = "no safe symbol or name"
                if reason:
                    excluded.append((chain, address, token["symbol"], reason))
                    continue
                kept.append(
                    {
                        "chain_id": chain,
                        "address": address,
                        "symbol": symbol,
                        "name": name,
                        "decimals": decimals,
                        "upgradeable": any(slot and int(slot, 16) for slot in slots),
                    }
                )
    kept.sort(key=lambda token: (token["chain_id"], token["address"]))
    print("[")
    print(",\n".join("  " + json.dumps(token, ensure_ascii=False) for token in kept))
    print("]")
    for chain, address, symbol, reason in excluded:
        print(f"excluded {chain} {address} {symbol}: {reason}", file=sys.stderr)
    print(f"kept {len(kept)}, excluded {len(excluded)}", file=sys.stderr)


if __name__ == "__main__":
    main()
