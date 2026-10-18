#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow==13.0.0", "cairosvg==2.9.1"]
# ///
"""Bundle address-bound token artwork; no image is fetched by the approval UI.

Run with: uv run scripts/bundle-token-artwork.py
Use --check for an offline integrity/coverage check. Curated lists and the
issuer registry propose images only for exact entries already in tokens.json.
Images are bounded, decoded and re-encoded as PNG; source bytes never ship.
The coverage manifest retains missing images instead of inventing artwork.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'crates/bloom-broker/src/ceremony_assets/tokens'
CATALOG = ROOT / 'crates/bloom-broker-api/tokens/tokens.json'
MANIFEST = ASSETS / 'artwork.json'
SOURCES = {
    'uniswap': 'https://cdn.jsdelivr.net/npm/@uniswap/default-token-list@22.27.0/build/uniswap-default.tokenlist.json',
    'gnosis': 'https://tokens.coingecko.com/xdai/all.json',
    'robinhood': 'https://api.robinhood.com/rhj/assets',
    'ethereum': 'https://tokens.coingecko.com/ethereum/all.json',
    'optimism': 'https://tokens.coingecko.com/optimistic-ethereum/all.json',
    'base': 'https://tokens.coingecko.com/base/all.json',
    'arbitrum': 'https://tokens.coingecko.com/arbitrum-one/all.json',
    'bsc': 'https://tokens.coingecko.com/binance-smart-chain/all.json',
    'polygon': 'https://tokens.coingecko.com/polygon-pos/all.json',
    'linea': 'https://tokens.coingecko.com/linea/all.json',
    'hyperevm': 'https://tokens.coingecko.com/hyperevm/all.json',
}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
ALLOWED_HOSTS = {
    'cdn.jsdelivr.net', 'tokens.coingecko.com', 'api.robinhood.com',
    'assets.coingecko.com', 'coin-images.coingecko.com', 'cdn.robinhood.com',
    'raw.githubusercontent.com', 's2.coinmarketcap.com', 'ipfs.io',
    'ethereum-optimism.github.io', 'static.optimism.io', 'www.geckoterminal.com', 'arbitrum.foundation',
    'basescan.org', 'assets.kraken.com', 'esm.sh', 'dynamic-assets.coinbase.com',
}


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError('artwork URL is outside the reviewed HTTPS hosts')


class ReviewedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        validate_url(url)
        return super().redirect_request(request, fp, code, message, headers, url)


def fetch(url, maximum=MAX_SOURCE_BYTES):
    validate_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'Bloom-token-artwork/1'})
    with urllib.request.build_opener(ReviewedRedirects()).open(request, timeout=20) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('artwork source exceeds size bound')
    return data


def image_url(value):
    if value.startswith('ipfs://'):
        value = 'https://ipfs.io/ipfs/' + value.removeprefix('ipfs://').removeprefix('ipfs/')
    return value


def safe_svg(data):
    # CairoSVG's XML parser rejects entities. Also forbid references that could
    # read a local file or make a second network request during rasterization.
    if re.search(br'<!DOCTYPE|<!ENTITY', data, re.I):
        raise ValueError('SVG declarations are not accepted')
    root = ET.fromstring(data)
    if root.tag.rsplit('}', 1)[-1] != 'svg':
        raise ValueError('not an SVG image')
    forbidden = {'script', 'foreignObject', 'image', 'iframe', 'style', 'text'}
    for node in root.iter():
        if node.tag.rsplit('}', 1)[-1] in forbidden:
            raise ValueError('SVG contains active, external or font-dependent content')
        for name, value in node.attrib.items():
            name = name.rsplit('}', 1)[-1].lower()
            if (name.startswith('on') or name == 'base' or '\\' in value
                    or (name == 'href' and not value.startswith('#'))):
                raise ValueError('SVG contains an external reference or handler')
            for reference in re.findall(r'url\(([^)]*)\)', value, re.I):
                if not reference.strip().strip('\'"').startswith('#'):
                    raise ValueError('SVG contains an external URL')


def normalize(data):
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 4_000_000
    if data.lstrip().startswith((b'<', b'<?xml')):
        import cairosvg
        safe_svg(data)
        data = cairosvg.svg2png(bytestring=data, output_width=128, output_height=128)
    with Image.open(io.BytesIO(data)) as source:
        if source.width * source.height > Image.MAX_IMAGE_PIXELS:
            raise ValueError('artwork dimensions exceed bound')
        image = ImageOps.contain(source.convert('RGBA'), (128, 128))
        canvas = Image.new('RGBA', (128, 128))
        canvas.alpha_composite(image, ((128 - image.width) // 2, (128 - image.height) // 2))
        output = io.BytesIO()
        canvas.save(output, format='PNG', optimize=True)
        return output.getvalue()


def proposed_images(source_documents):
    proposals = {}
    for source, document in source_documents.items():
        if source == 'robinhood':
            continue
        for token in document['tokens']:
            if token.get('logoURI'):
                key = (token['chainId'], token['address'].lower())
                candidate = (source, image_url(token['logoURI']))
                if key not in proposals or (proposals[key][1].startswith('https://ipfs.io/')
                                           and not candidate[1].startswith('https://ipfs.io/')):
                    proposals[key] = candidate
    for token in source_documents['robinhood']['assets']:
        if token.get('logoUrl') and token['status'] == 'ASSET_STATUS_ACTIVE':
            for deployment in token['deployments']:
                proposals[(deployment['chainId'], deployment['contractAddress'].lower())] = (
                    'robinhood', image_url(token['logoUrl']))
    return proposals


def generated_files(rows):
    images = sorted({row['file'] for row in rows if row.get('file', '').endswith('.png')})
    rust = ['// Generated by scripts/bundle-token-artwork.py; exact filename allowlist.',
            '#[rustfmt::skip]',
            "pub(crate) fn image(name: &str) -> Option<&'static [u8]> {", '    match name {']
    for name in images:
        rust.append(f'        "{name}" => Some(include_bytes!("ceremony_assets/tokens/generated/{name}")),')
    rust.extend(['        _ => None,', '    }', '}', ''])
    bindings = {f"{row['chain_id']}:{row['address']}": {
        'file': row['file'], 'name': row['name'], 'symbol': row['symbol']
    } for row in rows if row.get('file')}
    js = '// Generated from the address-bound token catalog; no runtime image network access.\n'
    js += 'const REVIEWED_TOKEN_ARTWORK = ' + json.dumps(bindings, ensure_ascii=True, separators=(',', ':')) + ';\n'
    return '\n'.join(rust), js


def check():
    manifest = json.loads(MANIFEST.read_text())
    rows = manifest['tokens']
    catalog = json.loads(CATALOG.read_text())
    neutral = json.loads((ASSETS / 'neutral-artwork.json').read_text())
    deployments = json.loads((ASSETS / 'deployment-artwork.json').read_text())
    issuer = json.loads((ASSETS / 'issuer-artwork.json').read_text())
    identity = lambda row: (row['chain_id'], row['address'], row['name'], row['symbol'])
    if [identity(row) for row in rows] != [identity(row) for row in catalog]:
        raise ValueError('artwork manifest does not match the current token catalog')
    for row in rows:
        key = f"{row['chain_id']}:{row['address']}"
        if key in neutral and (row.get('file') or row.get('missing_reason') != neutral[key]):
            raise ValueError('neutral artwork policy was overridden')
        if key in issuer and row.get('file') != issuer[key]:
            raise ValueError('issuer-reviewed artwork was overridden')
        if key in deployments and row.get('file') and row.get('identity_source') != deployments[key]['identity_source']:
            raise ValueError('reviewed deployment artwork lost its identity source')
        if row.get('file'):
            name = row['file']
            if name in ('usdc.svg', 'dai.svg') and row.get('source') == 'issuer-reviewed':
                data = (ASSETS / name).read_bytes()
                if hashlib.sha256(data).hexdigest() != row.get('sha256'):
                    raise ValueError('bundled artwork content differs from its digest')
                continue
            if not re.fullmatch(r'[0-9a-f]{64}\.png', name):
                raise ValueError('invalid bundled image name')
            data = (ASSETS / 'generated' / name).read_bytes()
            if not data.startswith(b'\x89PNG\r\n\x1a\n') or hashlib.sha256(data).hexdigest() + '.png' != name:
                raise ValueError('bundled artwork content differs from its digest')
        elif not row.get('missing_reason'):
            raise ValueError('missing artwork needs an explicit reason')
    rust, js = generated_files(rows)
    if (ASSETS.parents[1] / 'token_artwork.rs').read_text() != rust:
        raise ValueError('Rust artwork allowlist is stale')
    if (ASSETS.parent / 'token-artwork.js').read_text() != js:
        raise ValueError('browser artwork bindings are stale')
    print(f"Artwork integrity passed: {sum(bool(row.get('file')) for row in rows)}/{len(rows)} catalog entries")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--sources-dir', type=Path, help='read cached public source documents')
    parser.add_argument('--refresh-images', action='store_true', help='refetch successful image URLs too')
    args = parser.parse_args()
    if args.check:
        check()
        return
    def source(name, url):
        cached = args.sources_dir / (name + '.json') if args.sources_dir else None
        if cached and cached.exists():
            return json.loads(cached.read_text())
        data = fetch(url, 8 * MAX_SOURCE_BYTES)
        if cached:
            cached.write_bytes(data)
        return json.loads(data)
    source_documents = {name: source(name, url) for name, url in SOURCES.items()}
    proposals = proposed_images(source_documents)
    tokens = json.loads(CATALOG.read_text())
    issuer = json.loads((ASSETS / 'issuer-artwork.json').read_text())
    neutral = json.loads((ASSETS / 'neutral-artwork.json').read_text())
    deployments = json.loads((ASSETS / 'deployment-artwork.json').read_text())
    known = {f"{row['chain_id']}:{row['address']}" for row in tokens}
    if not set(issuer).issubset(known) or any(name not in ('usdc.svg', 'dai.svg') for name in issuer.values()):
        raise ValueError('issuer artwork is not bound to known catalog identities')
    if not set(neutral).issubset(known) or set(issuer) & set(neutral):
        raise ValueError('neutral artwork policy has unknown or conflicting identities')
    if not set(deployments).issubset(known) or set(deployments) & (set(issuer) | set(neutral)):
        raise ValueError('deployment artwork has unknown or conflicting identities')
    for key, deployment in deployments.items():
        chain, address = key.split(':')
        proposals[(int(chain), address)] = ('reviewed-deployment', deployment['source_url'])
    # The issuer's image registry is keyed by the exact deployed contract.
    # Keep artwork available for held tokens removed from its active list.
    for token in tokens:
        if token['chain_id'] == 4663:
            proposals.setdefault((4663, token['address']), (
                'robinhood', f"https://cdn.robinhood.com/ncw_assets/logos/{token['address']}.png"))
    urls = sorted({proposals[(row['chain_id'], row['address'])][1] for row in tokens
                   if (row['chain_id'], row['address']) in proposals
                   and f"{row['chain_id']}:{row['address']}" not in issuer
                   and f"{row['chain_id']}:{row['address']}" not in neutral})

    cached_images = {}
    if MANIFEST.exists() and not args.refresh_images:
        for row in json.loads(MANIFEST.read_text())['tokens']:
            if row.get('file') and re.fullmatch(r'[0-9a-f]{64}\.png', row['file']):
                path = ASSETS / 'generated' / row['file']
                if path.exists():
                    data = path.read_bytes()
                    if hashlib.sha256(data).hexdigest() + '.png' == row['file']:
                        cached_images[row['source_url']] = data

    def download(url):
        try:
            data = cached_images[url] if url in cached_images else normalize(fetch(url))
            return url, (data, None)
        except Exception as error:
            return url, (None, type(error).__name__ + ': ' + str(error)[:160])

    with ThreadPoolExecutor(max_workers=8) as workers:
        downloads = dict(workers.map(download, urls))
    output = ASSETS / 'generated'
    output.mkdir(exist_ok=True)
    rows = []
    for token in tokens:
        row = {key: token[key] for key in ['chain_id', 'address', 'symbol', 'name']}
        reason = neutral.get(f"{token['chain_id']}:{token['address']}")
        if reason:
            row.update(source='reviewed-neutral', missing_reason=reason)
            rows.append(row)
            continue
        original = issuer.get(f"{token['chain_id']}:{token['address']}")
        if original:
            row.update(source='issuer-reviewed', file=original,
                       sha256=hashlib.sha256((ASSETS / original).read_bytes()).hexdigest())
            rows.append(row)
            continue
        proposal = proposals.get((token['chain_id'], token['address']))
        if proposal:
            source, url = proposal
            row.update(source=source, source_url=url)
            deployment = deployments.get(f"{token['chain_id']}:{token['address']}")
            if deployment:
                row['identity_source'] = deployment['identity_source']
            data, error = downloads[url]
            if data:
                name = hashlib.sha256(data).hexdigest() + '.png'
                (output / name).write_bytes(data)
                row['file'] = name
            else:
                row['missing_reason'] = error
        else:
            row['missing_reason'] = 'No exact chain/address image in the curated sources'
        rows.append(row)
    manifest = {'sources': {name: {'url': SOURCES[name], 'sha256': hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        for name, document in source_documents.items()}, 'tokens': rows}
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + '\n')
    rust, js = generated_files(rows)
    (ASSETS.parents[1] / 'token_artwork.rs').write_text(rust)
    (ASSETS.parent / 'token-artwork.js').write_text(js)
    check()


if __name__ == '__main__':
    main()
