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

Initial identities: Ethereum (chain 1) USDC at
`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` and DAI at
`0x6B175474E89094C44Da98b954EedeAC495271d0F`.
