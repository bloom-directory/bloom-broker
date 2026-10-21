# Bundled token artwork

The renderer selects these decorative images by chain ID and full contract
address. Names and amounts still come from the review; the full address stays
visible. Unknown tokens use the generic icon. Adding a token requires a code
review, including its chain, contract address, artwork and source.

`artwork.json` records coverage and missing-image reasons for every entry in
the current shared token catalog. It retains source URLs and source-document
digests as build provenance. `deployment-artwork.json` records the additional
reviewed deployment bindings. Neither file is fetched by the ceremony page.

The recovered pipeline is `scripts/bundle-token-artwork.py`. It bounds source
size and image dimensions, rejects active/external SVG content, and normalizes
images to 128×128 PNGs. Content-hash filenames deduplicate identical bytes.
The generated browser mapping selects exact chain/address pairs; the generated
Rust allowlist serves only compiled image bytes. There is no remote-image or
ticker-based lookup. `python3 scripts/bundle-token-artwork.py --check` verifies
catalog agreement, policy exceptions, file hashes, dimensions and generated
outputs offline. CI also runs its source-boundary tests.

- `usdc.svg`: unchanged `Token Logo/USDC Token.svg` from
  [Circle's brand kit](https://www.circle.com/pressroom), downloaded 2026-09-23
  ([archive](https://6778953.fs1.hubspotusercontent-na1.net/hubfs/6778953/Pressroom/brandkit/logo-downloads/usdc.zip)).
  Circle retains its trademark rights.
- `dai.svg`: Dai glyph from MakerDAO's
  [dai-ui icons](https://github.com/sky-ecosystem/dai-ui/blob/7830d8b8a16bd7409b02a7377944ec020218e9f2/packages/dai-ui-icons-branding/lib/index.js),
  under Apache-2.0 (see `DAI-LICENSE.txt`). Adapted from JSX to SVG,
  colored white and placed on a gold circle.

The SVG identities are retained in `issuer-artwork.json`; the complete generated
mapping is `../token-artwork.js`. Missing or representation-specific artwork
stays neutral under `neutral-artwork.json`, including pUSD: Circle's USDC logo
must never stand in for it. Metadata support does not imply current contract
behavior or endorsement by an image provider; trademark rights remain with
their respective owners.
