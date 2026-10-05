# Conservative ceremony startup improvement

Base: `5095af43ad22994cb0a0bdad07a1d7adcf2410eb` (exact PR73 head).
This is an isolated local candidate, not the installed 0.4.0 release.

## Audit and change

- Read the sibling Machine AGENTS/development/testing/compatibility guidance;
  this Broker checkout contains no AGENTS.md. Read the independent latency audit.
- Exchange adds only `snapshot.projection`, the existing `BrowserProjection`
  served by authorized GET. A Rust HTTP test requires exact JSON equality and
  exactly three exchange fields. Never serialize `BrowserSession`.
- Fresh remote JS uses that projection in memory and omits GET session.
  Reload, local mode, and older-server fallback retain GET session. Storage
  still contains only ceremony ID, CSRF, and expiry, never a projection.
- Crypto self-test and existing storage cleanup remain awaited before any API
  call. Cleanup retains its existing best-effort error semantics. No new
  background work, optimistic result race, or waiting-page protocol was added.
- GET result remains awaited before review/approval, including the fresh path.
- A terminal UI latch prevents late normal-flow passkey callbacks from enabling
  or posting completion after observed cancellation/expiry/completion. Expiry
  is checked before enable, before passkey invocation, before completion POST,
  and before retry enable, including throttled-timer cases.
- Exact bytes, challenges, WebAuthn options, HPKE AAD, server replay checks,
  expiry budget, nonces and transaction normalization are unchanged.
- Caching is deliberately separate: HTML, API, and static responses retain
  existing no-store/security middleware. No cache headers or routes changed.

## TDD evidence

Tests were run RED before each behavior change, then GREEN:

1. Rust `remote_fragment_is_single_use_and_cookie_is_ceremony_scoped`:
   failed equality (`Null` exchange session versus authorized GET projection),
   then passed after adding only `snapshot.projection`.
2. Chromium fresh load: failed expected 2 API calls, observed 3 (690.3 ms at
   200 ms injected API delay), then passed with 2 calls (482.5 ms in first GREEN).
3. Already expired load: failed `Expired ceremony enabled Approve`, then passed.
4. Late passkey rejection after expiry: failed `late-expiry-failure re-enabled
   Approve`, then passed with expiry latch.
5. Late rejection after cancellation: same re-enable failure, then passed with
   cancellation latch.
6. Completed-result late failure: failed `Completed flow re-enabled Approve`,
   then passed with completion latch.
7. Late passkey success after expiry: failed no-completion-POST assertion,
   then passed. Cancellation success regression also passes.
8. Throttled timer expiry after passkey success: failed no-completion-POST
   assertion, then passed with direct expiry recheck.
9. Throttled timer expired click: failed `Expired click prompted`, then passed.
10. Throttled timer late failure: failed retry-enable assertion, then passed.

A prior exact-source-string test expected the old `.catch(reportApprovalFailure)`
callback. It was updated to require the guarded wrapper; its executable Node
error-feedback assertions remain intact. No production behavior was changed
just to satisfy that string assertion.

## Final runnable checks

From the repository root (use a distinct `CARGO_TARGET_DIR`):

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p bloom-broker --locked
```

Results: workspace **343 passed, 0 failed, 1 ignored**; fmt, clippy and debug
build passed. The ignored test is not claimed as exercised.

Real Chromium test (Playwright 1.63.0 / Chromium 153.0.8010.12):

```sh
uv venv .venv
uv pip install --python .venv/bin/python playwright==1.63.0
.venv/bin/python -m playwright install chromium
.venv/bin/python scripts/test-ceremony-load.py
.venv/bin/python scripts/test-ceremony-load.py --baseline --case fresh
```

All **19 cases** pass: fresh, expired, failed/deferred crypto, deferred real
IndexedDB open, held result, recoverable completed result, reload, completed
reload, older server, identity mismatch, result error, late expiry/cancel
success/failure, and expiry with throttled timers before click or after passkey
success/failure. Shipped HTML/JS execute unmodified. API responses and passkey
results are synthetic and restricted to `https://ceremony.invalid`; no wallet
operations or real passkeys are performed. Rust HTTP tests separately exercise
actual exchange authentication, projection, one-use and cookie handling.

This host lacked Chromium shared libraries. Downloaded distro packages were
extracted to scratch and supplied through `LD_LIBRARY_PATH`; no sudo/system
package installation or installed Bloom modification was made.

## Paired load measurements

Five alternating baseline/candidate runs, fresh browser contexts, 200 ms delay
injected **per API response**; shipped asset bytes are fulfilled locally. The
baseline uses the exact base commit JS via `git show`, not a rewritten imitation.
Time is navigation `performance.now()` when Approve first becomes enabled.

| | Serial APIs before enable | Ready milliseconds, 5 samples | Median |
|---|---:|---|---:|
| Base | 3: exchange -> session -> result | 725.7, 704.1, 714.6, 679.3, 695.8 | 704.1 |
| Candidate | 2: exchange -> result | 482.9, 496.2, 506.4, 479.1, 503.4 | 496.2 |

Median difference: **207.9 ms** under this injected-delay fixture. Reload remains
2 serial APIs. This is evidence of one removed dependency round trip, not a
claim about phone latency, real HTTPS/relay timing, blockhash lifetime, or time
from passkey tap to on-chain settlement. Public cold-connection curl timings
were not substituted for browser measurements.

## Deployment and coverage limits

- No push/PR, live relay session, real wallet ceremony, signing or broadcast.
  `/usr/libexec/bloom/current` and funded services were not modified.
- Debug Broker build is available under the isolated target directory; it is
  not a signed release artifact. An attempted `--help` invocation entered the
  normal bootstrap path and failed closed before trusted service metadata was
  loaded; this binary does not offer that standalone help mode. No running
  candidate triad or installed-principal acceptance is claimed.
- Do not swap this binary into production. Release compatibility must be
  established at explicit Machine/Broker/Signer pins, followed by signed
  packaging and operator-controlled installation. The sibling Machine release
  manifest pins a different Broker commit and cannot establish compatibility.
- `/result` 409 is **not** evidence of AwaitingUser: terminal/failed states can
  also return 409. This patch intentionally preserves the existing awaited
  result protocol and server authority; it does not claim to solve every
  terminal resume state or cross-tab UI status. The completed browser fixture
  covers retained/recoverable 200 results, not all ordinary terminal states.
  There is no new background result race. No generic fresh-state shortcut was
  introduced.
- Sensitive output recipient recovery, cross-surface enrollment, real-device
  passkeys, mobile lifecycle, and real triad end-to-end acceptance need their
  existing dedicated/live gates before a release. Existing workspace tests
  passed, but the added browser fixture does not replace those gates.
