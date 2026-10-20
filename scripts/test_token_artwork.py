"""Offline identity checks for the curated artwork set."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "crates/bloom-broker/src/ceremony_assets"


class ArtworkBoundaryTests(unittest.TestCase):
    def test_mapping_is_exactly_the_reviewed_issuer_set(self):
        source = (ASSETS / "token-artwork.js").read_text()
        mapping = json.loads(source[source.index("{"):source.rindex(";")])
        issuers = json.loads((ASSETS / "tokens/issuer-artwork.json").read_text())
        self.assertEqual({key: value["file"] for key, value in mapping.items()}, issuers)
        for filename in issuers.values():
            self.assertTrue((ASSETS / "tokens" / filename).is_file())
        for key in json.loads((ASSETS / "tokens/neutral-artwork.json").read_text()):
            self.assertNotIn(key, mapping)
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        self.assertIn("1:" + usdc, mapping)
        self.assertNotIn("8453:" + usdc, mapping)
        self.assertNotIn("1:0x" + "11" * 20, mapping)

    def test_no_generated_png_serving(self):
        ceremony = (ROOT / "crates/bloom-broker/src/ceremony.rs").read_text()
        self.assertNotIn("token_artwork::image", ceremony)
        self.assertFalse((ASSETS / "tokens/generated").exists())


if __name__ == "__main__":
    unittest.main()
