# Bundled token artwork

The renderer selects these decorative images by chain ID and full contract
address. Names and amounts still come from the review; the full address stays
visible. Unknown tokens use the generic icon. Adding a token requires a code
review, including its chain, contract address, artwork and source.

- `usdc.svg`: unchanged `Token Logo/USDC Token.svg` from
  [Circle's brand kit](https://www.circle.com/pressroom), downloaded 2026-09-23
  ([archive](https://6778953.fs1.hubspotusercontent-na1.net/hubfs/6778953/Pressroom/brandkit/logo-downloads/usdc.zip)).
  Circle retains its trademark rights.
- `dai.svg`: Dai glyph from MakerDAO's
  [dai-ui icons](https://github.com/sky-ecosystem/dai-ui/blob/7830d8b8a16bd7409b02a7377944ec020218e9f2/packages/dai-ui-icons-branding/lib/index.js),
  under Apache-2.0 (see `DAI-LICENSE.txt`). Adapted from JSX to SVG,
  colored white and placed on a gold circle.

The identities are the `logos` table in `app.js`: Circle-issued USDC on
chains 1, 10, 137, 999, 8453, 42161, 43114 and 59144, and DAI on chains 1,
10, 42161 and 8453.
