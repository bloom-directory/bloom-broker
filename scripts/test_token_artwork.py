import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    'artwork', Path(__file__).with_name('bundle-token-artwork.py'))
artwork = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artwork)


class ArtworkBoundaryTests(unittest.TestCase):
    def test_svg_cannot_read_files_fetch_resources_or_execute_handlers(self):
        for body in [
            '<use href="file:///private.svg"/>',
            '<use href="https://example.com/remote.svg"/>',
            '<path style="fill:url(https://example.com/pattern)"/>',
            '<path onload="alert(1)"/>',
            '<script>alert(1)</script>',
            '<foreignObject/>',
            '<g xml:base="https://example.com/"><use href="#p"/></g>',
            r'<path style="fill:u\72l(https://example.com/pattern)"/>',
        ]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                artwork.safe_svg(('<svg xmlns="http://www.w3.org/2000/svg">' + body + '</svg>').encode())
        with self.assertRaises(ValueError):
            artwork.safe_svg(b'<!DOCTYPE svg [<!ENTITY secret SYSTEM "file:///secret">]><svg/>')
        artwork.safe_svg(b'<svg><defs><path id="p" d="M0 0"/></defs><use href="#p"/></svg>')

    def test_unreviewed_hosts_credentials_and_redirects_are_not_fetched(self):
        for url in ['file:///private.png', 'http://assets.coingecko.com/a.png',
                    'https://localhost/a.png', 'https://assets.coingecko.com:18734/a.png',
                    'https://user:password@assets.coingecko.com/a.png',
                    'https://assets.coingecko.com.attacker.example/a.png']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                artwork.validate_url(url)
        artwork.validate_url('https://assets.coingecko.com/a.png')
        with self.assertRaises(ValueError):
            artwork.ReviewedRedirects().redirect_request(None, None, 302, '', {}, 'file:///private.png')

    def test_same_ticker_never_grants_another_address_or_chain_its_artwork(self):
        token = {'chainId': 1, 'address': '0x' + '11' * 20,
                 'symbol': 'USDC', 'logoURI': 'https://assets.coingecko.com/usdc.png'}
        proposals = artwork.proposed_images({
            'uniswap': {'tokens': [token]}, 'robinhood': {'assets': []}})
        self.assertIn((1, token['address']), proposals)
        self.assertNotIn((8453, token['address']), proposals)
        self.assertNotIn((1, '0x' + '22' * 20), proposals)

    def test_bundled_image_tampering_is_detected_offline(self):
        with patch.object(Path, 'read_bytes', return_value=b'\x89PNG\r\n\x1a\ntampered'):
            with self.assertRaisesRegex(ValueError, 'content differs'):
                artwork.check()


if __name__ == '__main__':
    unittest.main()
