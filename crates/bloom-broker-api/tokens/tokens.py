#!/usr/bin/env python3
"""Regenerate tokens.json, the token list Broker and Machine both compile in,
from curated token lists, checked on chain.

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
# Robinhood's Stock Tokens, from the issuer's own registry.
ROBINHOOD = "https://api.robinhood.com/rhj/assets"
RPC = {
    1: "https://ethereum-rpc.publicnode.com",
    10: "https://optimism-rpc.publicnode.com",
    100: "https://gnosis-rpc.publicnode.com",
    137: "https://polygon-bor-rpc.publicnode.com",
    8453: "https://base-rpc.publicnode.com",
    42161: "https://arbitrum-one-rpc.publicnode.com",
    4663: "https://rpc.mainnet.chain.robinhood.com",
    56: "https://bsc-rpc.publicnode.com",
    43114: "https://avalanche-c-chain-rpc.publicnode.com",
    59144: "https://linea-rpc.publicnode.com",
    999: "https://rpc.hyperliquid.xyz/evm",
    4217: "https://rpc.tempo.xyz",
}
# Majors no curated list carries (liquid staking tokens, sUSDS, and chains
# Uniswap does not list), taken from the Enso Petal's hand-checked table.
# Their labels are read from the chain; a third field is the fallback label.
EXTRA = {
    1: [
        ("0xae78736cd615f374d3085123a210448e74fc6393", 18),  # RETH
        ("0xa3931d71877c0e7a3148cb7eb4463524fec27fbd", 18),  # SUSDS
        ("0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee", 18),  # WEETH
        ("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0", 18),  # WSTETH
    ],
    10: [
        ("0x9bcef72be871e61ed4fbbc7630889bee758eb81d", 18),  # RETH
        ("0xb5b2dc7fd34c249f4be7fb1fcea07950784229e0", 18),  # SUSDS
        ("0x4f13a96ec5c4cf34e442b46bbd98a0791f20edc3", 18),  # USDS
        ("0x5a7facb970d094b6c7ff1df0ea68d99e6e73cbff", 18),  # WEETH
        ("0x1f32b1c2345538c0c6f582fcb022739c4a194ebb", 18),  # WSTETH
    ],
    56: [
        ("0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c", 18),  # BTCB
        ("0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", 18),  # CAKE
    ],
    137: [
        ("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb", 6),  # Polymarket USD
        ("0x0b3f868e0be5597d5db7feb59e1cadbb0fdda50a", 18),  # SUSHI
        ("0x03b54a6e9a984069379fae1a4fc4dbae93b3bccd", 18),  # WSTETH
    ],
    999: [
        ("0x9fdbda0a5e284c32744d2f17ee5c74b284993463", 8),  # UBTC
        ("0xbe6727b535545c67d5caa73dea54865b92cf7907", 18),  # UETH
        ("0xb88339cb7199b77e23db6e890353e22632ba630f", 6),  # USDC
        # Its own symbol is "USD₮0", which a label may not carry.
        ("0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb", 6, "USDT0"),
        ("0x5555555555555555555555555555555555555555", 18),  # WHYPE
    ],
    4217: [
        ("0x20c0000000000000000000000520792dcccccccc", 6),  # CUSD
        ("0x20c0000000000000000000001621e21f71cf12fb", 6),  # EURC
        ("0x20c0000000000000000000000000000000000000", 6),  # PATHUSD
    ],
    4663: [
        ("0x0bd7d308f8e1639fab988df18a8011f41eacad73", 18),  # WETH
    ],
    8453: [
        ("0xb6fe221fe9eef5aba221c348ba20a1bf5e73624c", 18),  # RETH
        ("0x5875eee11cf8398102fdad704c9e96607675467a", 18),  # SUSDS
        ("0x820c137fa70c8691f0e44dc420a5e53c168921dc", 18),  # USDS
        ("0x04c0599ae5a44757c0af6f9ec3b93da8976c150a", 18),  # WEETH
        ("0xc1cba3fcea344f92d9239c08c0568f6f2f0ee452", 18),  # WSTETH
    ],
    42161: [
        ("0xec70dcb4a1efa46b8f2d97c310c9c4790ba5ffa8", 18),  # RETH
        ("0xddb46999f8891663a8f2828d25298f70416d7610", 18),  # SUSDS
        ("0x35751007a407ca6feffe80b3cb397736d2cf4dbe", 18),  # WEETH
        ("0x5979d7b546e38e414f7e9822514be443a4800529", 18),  # WSTETH
    ],
    59144: [
        ("0x4af15ec2a0bd43db75dd04e62faa3b8ef36b00d5", 18),  # DAI
        ("0x1789e0043623282d5dcc7f213d703c6d8bafbb04", 18),  # LINEA
        ("0xaca92e438df0b2401ff60da7e4337b687a2435da", 6),  # MUSD
        ("0x176211869ca2b568f2a7d4ee941e073a821ee1ff", 6),  # USDC
        ("0xa219439258ca9da29e9cc4ce5596924745e12b93", 6),  # USDT
        ("0x3aab2285ddcddad8edf438c1bab47e1a9d05a9b4", 8),  # WBTC
        ("0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f", 18),  # WETH
        ("0xb5bedd42000b71fdde22d3ee8a79bd49a568fc8f", 18),  # WSTETH
    ],
}
PROXY_SLOTS = [
    # EIP-1967 implementation
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    # ZeppelinOS implementation (Circle FiatToken)
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
]
DECIMALS, SYMBOL, NAME = "0x313ce567", "0x95d89b41", "0x06fdde03"
# Tokens per RPC request (six calls each). Robinhood's endpoint rate-limits
# large batches; HyperEVM's accepts at most 20 calls.
BATCH = {4663: 2, 999: 3}


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
    for attempt in range(10):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                replies = json.load(response)
            if not isinstance(replies, list):
                raise RuntimeError(f"chain {chain}: {replies}")
            replies = {reply["id"]: reply.get("result") for reply in replies}
            time.sleep(0.5)
            return [replies.get(i) for i in range(len(calls))]
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 9:
                raise RuntimeError(f"chain {chain}: {error}") from error
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
    stocks = [
        {
            "chainId": deployment["chainId"],
            "address": deployment["contractAddress"],
            "symbol": asset["tokenSymbol"],
            "name": asset["tokenName"],
            "decimals": asset["tokenDecimals"],
        }
        for asset in get(ROBINHOOD)["assets"]
        if asset["status"] == "ASSET_STATUS_ACTIVE"
        for deployment in asset["deployments"]
    ]
    lists = [
        (get(UNISWAP.format(UNISWAP_VERSION))["tokens"], True),
        (get(GNOSIS)["tokens"], False),
        (stocks, True),
        (
            [
                {"chainId": chain, "address": address, "decimals": decimals,
                 "symbol": "".join(label), "name": "".join(label)}
                for chain, rows in EXTRA.items()
                for address, decimals, *label in rows
            ],
            False,
        ),
    ]
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
        size = BATCH.get(chain, 20)
        for start in range(0, len(tokens), size):
            batch = tokens[start : start + size]
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
