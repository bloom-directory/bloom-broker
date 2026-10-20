"""Synthetic captured inputs test derivation, not historical chain provenance."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tokens", ROOT / "crates/bloom-broker-api/tokens/tokens.py")
tokens = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tokens)


class DerivationTests(unittest.TestCase):
    def inputs(self):
        rows = [
            {"chainId": 1, "address": "0x" + "11" * 20, "symbol": "USDC", "name": "Example USDC", "decimals": 6},
            {"chainId": 137, "address": "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb", "symbol": "pUSD", "name": "Polymarket USD", "decimals": 6},
        ]
        source_data = {
            tokens.UNISWAP.format(tokens.UNISWAP_VERSION): {"tokens": rows},
            tokens.GNOSIS: {"tokens": []}, tokens.ROBINHOOD: {"assets": []},
        }
        scope = [f"{row['chainId']}:{row['address']}" for row in rows]
        return {"schema": 1, "scope": scope,
            "sources": {url: {"data": data, "sha256": hashlib.sha256(tokens.canonical(data)).hexdigest()}
                        for url, data in source_data.items()},
            "blocks": {str(row["chainId"]): {"number": "0x123", "hash": "0x" + "22" * 32} for row in rows},
            "observations": [{"chain_id": row["chainId"], "address": row["address"],
                "token": {**row, "curated": True}, "proxy_slots": tokens.PROXY_SLOTS,
                "results": ["0x60", "0x" + f"{6:064x}", "0x", "0x"] + ["0x" + "00" * 32] * 2}
                for row in rows]}

    def test_deterministic_derivation_and_identity_mutations(self):
        document = self.inputs()
        with patch.object(tokens, "get", side_effect=AssertionError("network")):
            rows, excluded = tokens.offline(document)
            self.assertFalse(excluded)
            self.assertEqual(rows, tokens.offline(copy.deepcopy(document))[0])
            self.assertEqual([row["symbol"] for row in rows], ["USDC", "pUSD"])
            for field, value in [("address", "0x" + "33" * 20), ("chain_id", 8453)]:
                changed = copy.deepcopy(document)
                changed["observations"][0][field] = value
                with self.assertRaises(ValueError):
                    tokens.offline(changed)
            changed = copy.deepcopy(document)
            changed["observations"][0]["results"][1] = "0x" + f"{18:064x}"
            derived, excluded = tokens.offline(changed)
            self.assertEqual(len(derived), 1)
            self.assertTrue(excluded)
            changed = copy.deepcopy(document)
            next(iter(changed["sources"].values()))["data"]["tokens"][0]["symbol"] = "FAKE"
            with self.assertRaisesRegex(ValueError, "digest"):
                tokens.offline(changed)

    def test_capture_refuses_a_block_changed_during_reads(self):
        def rpc(chain, calls):
            if calls[0][0] == "eth_getBlockByNumber":
                return [{"number": "0x1", "hash": "0x" + ("11" if calls[0][1][0] == "latest" else "22") * 32}]
            return ["0x"] * len(calls)
        candidate = self.inputs()["observations"][0]["token"]
        with patch.object(tokens, "candidates", return_value=iter([candidate])), patch.object(tokens, "rpc", side_effect=rpc):
            with self.assertRaisesRegex(ValueError, "block changed"):
                tokens.capture()


if __name__ == "__main__":
    unittest.main()
