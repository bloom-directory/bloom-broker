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
  manifest inspected during the original run pinned a different Broker commit.
  See the PR-readiness follow-up below for the newly inspected candidate pins.
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

## PR-readiness follow-up (uncommitted working tree)

Tested starting HEAD: `21a2c45c92d2c79ea4e677026ecc82895b62b439`.
Diff base remains `5095af43ad22994cb0a0bdad07a1d7adcf2410eb` (PR73),
not current master. No commits, remote writes, service installation, funded keys,
or live triad launch were performed in this follow-up.

### Proved regression and minimal fix

The terminal latch also suppressed failures from `finishBrowserResult` after a
successful completion POST. A fresh wallet-export browser fixture generated a
real HPKE envelope with deliberately mismatched AAD, then exercised the shipped
decryption code. RED failed with:

```text
AssertionError: Result decryption failure was silently presented as Completed.
```

The fix catches result processing errors immediately around the awaited
`finishBrowserResult` call in `run`, reports that result recovery or acknowledgement
failed, and leaves approval disabled. It does not retry completion, alter crypto,
clear the saved recipient on failure, or relax the late-passkey guard. GREEN
passed with one completion POST and no acknowledgement. Added adjacent Chromium
cases verify a 503 acknowledgement failure retains the real IndexedDB recipient
and session reference, and successful authenticated output rendering plus ack
clears both. Test plaintext is the literal `synthetic-test-output`, not a wallet
secret. API responses and WebAuthn responses remain synthetic; HPKE, IndexedDB,
DOM events, and shipped app code execute in actual Chromium.

### Review and expanded checks

- Inspected the full candidate diff against PR73 and the surrounding exchange,
  cookie authorization, projection, startup, result, and cancellation paths.
- Exchange still requires exact Host/Origin, JSON content type, same-origin
  Fetch Metadata, live AwaitingUser state, and a single-use capability. The new
  response is exactly the existing public projection, not `BrowserSession`.
- Extended the real Axum HTTP test with six hostile/missing-header requests:
  each receives an empty 403, no cookie and `Cache-Control: no-store`, without
  consuming the valid link. Two joined exchanges yield exactly one success and
  one empty 403. This is an in-process one-use check, not a multi-process stress
  test. Existing scoped-cookie, duplicate-cookie, CSRF, and exact-projection
  assertions remain exercised.
- No new authorization, expiry, CSRF, or projection-leakage regression was found
  in the reviewed diff. The only proved new defect was suppressed result errors.
  Existing terminal-409 and cross-surface limitations above remain; absence of a
  result is not an authoritative live-state signal.

### Reproduce on this host without reinstalling dependencies

The existing venv, extracted browser libraries and Cargo target were reused.
All build/browser scratch remains on the large volume. The library path needs
the `root/` component (omitting it causes missing `libatk-1.0.so.0`).

```sh
export TMPDIR=/mnt/HC_Volume_102187271/hermes/cache/scratch
export CARGO_TARGET_DIR="$TMPDIR/ceremony-fast-load-target"
export LD_LIBRARY_PATH="$TMPDIR/ceremony-browser-libs/root/usr/lib/x86_64-linux-gnu"

"$TMPDIR/ceremony-browser-venv/bin/python" scripts/test-ceremony-load.py
"$TMPDIR/ceremony-browser-venv/bin/python" scripts/test-ceremony-load.py --baseline --case fresh
cargo test -p bloom-broker --test w5_ceremony --locked \
  remote_fragment_is_single_use_and_cookie_is_ceremony_scoped -- --exact
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p bloom-broker --locked
git diff --check
```

Follow-up results: **22/22 Chromium cases**, workspace **343 passed, 0 failed,
1 ignored**, targeted HTTP test **1 passed / 56 filtered**, fmt, clippy, debug
build and whitespace checks passed. The ignored ACME staging test was not run.
One baseline fresh measurement was **725.9 ms / 3 serial APIs**; the final
candidate fresh measurement was **508.0 ms / 2 serial APIs**, each at 200 ms
injected API delay. These are fixture observations, not paired phone timings.
Logs: `$TMPDIR/ceremony-pr-browser.jsonl` and
`$TMPDIR/ceremony-pr-workspace.log`.

Frozen production files for the parent build (SHA-256):

```text
2fd09cfc7ed450a42c630263185672753674a823976f33a9c660cf73b858d07d  crates/bloom-broker/src/ceremony_assets/app.js
d02a204bf45c094beadb14375bcb92a4709cce10e461cd442834d7c266158df5  crates/bloom-broker/src/ceremony.rs
```

### Remaining acceptance and ownership (before parent follow-up below)

The parent's exact Machine `059f900` checkout now pins baseline Broker
`5095af43ad22994cb0a0bdad07a1d7adcf2410eb`, Signer
`bc88ad690757165ebf1978410ea5c7ec652215d3`, and service-runtime
`ad0072512bb97fb4eb68d249ce785ea3ea4a49ab`. This is a compatible candidate to
test, not evidence that this modified Broker has passed live integration.

1. Parent: build this frozen Broker working tree, record binary digest and exact
   three-service revisions, and run the affected operation through an isolated,
   disposable real triad. Do not use installed services or production custody.
2. Before claiming live browser integration: exercise the candidate's actual
   served assets and authenticated exchange/result routes against that triad;
   verify fresh and resumed review, exact ceremony identity/terms, cancellation,
   expiry refusal and successful authorized completion. Routed synthetic APIs
   in this harness do not establish live cookie/relay or Signer acceptance.
3. Sensitive-output recovery and cross-surface enrollment still need their
   dedicated live gates; physical passkeys/mobile lifecycle and hosted HTTPS
   latency are deferred, not required from this follow-up and not claimed.
4. Before release: required CI/review, explicit compatibility/release pinning,
   signed packaging and principal-isolation acceptance remain mandatory. This
   branch is stacked on unmerged PR73; an eventual PR should target that branch
   unless rebased and retested. No publication was attempted here.

## Parent follow-up: real services and hosted HTTPS passed

The frozen revised app.js hash above was built with `cargo +1.98.1 build --release --locked -p bloom-broker -p bloom-broker-debug-driver --features triad-dev-harness`. Broker binary SHA-256: `25affd84205074cc756374a11b3823f36d5872d964fda9bc71533e723b29e8fa`. Machine `059f900` and Signer `bc88ad6` were selected explicitly; no production services were touched.

- Three real local-validator sends passed in `/home/kyle/b/sf-local` with a generated software-authenticator identity, live Broker ACTIVE, one helper confirm per entry, Signer signing, finalized error-free receipts, and restart refusal. The helper repository's REVISED-ACCEPTANCE.md records public signatures and phase timings. This exercises the revised Broker, but is not browser passkey completion.
- Real Chromium loaded the actual served candidate and used real Broker APIs, without interception/mocked replies. Local fresh/reload/output-key binding and cancel passed; cancellation was read back over Machine IPC.
- A new isolated relay allocation stayed `certificate_pending` with TLS/routing false. This was not treated as a product defect or bypassed. Parent preserved old test logs, stopped the existing disposable triad launcher, and restarted that established test identity/origin with the exact revised binaries. Its existing certificate and routing became healthy; no identity reset was used.
- At `https://bidjlrxtkhkdqy3q72e3wpnrti.relay.bloom.directory`, the real HTTPS suite then passed fresh exchange projection/no redundant session GET, exact operation identity, restricted sessionStorage, Secure/HttpOnly/SameSite=Strict host cookie, denial of consumed-link replay in an independent context, original-context reload, cancellation and natural expiry. Cancellation and expiry were independently confirmed over Machine IPC. The exact served app.js hash was checked.
- The first remote runner attempt encountered Chromium's unavailable body handle for an empty denied response; the harness now checks actual HTTP 403 and Content-Length: 0 rather than trying to retrieve the absent body. That disposable operation was cancelled and read back before the final run. No candidate code change was needed.

Public report: [evidence/remote-verified.json](evidence/remote-verified.json). Raw runner/evidence: `/mnt/HC_Volume_102187271/hermes/cache/scratch/solfast-pr-readiness/browser-live/`.

```sh
P=/mnt/HC_Volume_102187271/hermes/cache/scratch
"$P/ceremony-browser-venv/bin/python" \
  "$P/solfast-pr-readiness/browser-live/acceptance.py" \
  --run remote --expiry --expiry-budget 340 --report remote-verified.json
```

The runner is configured for the existing disposable Machine socket `/home/kyle/b/solfast-it/m.sock` and local asset port 28749. It creates disposable registrations and performs cancellation/natural-expiry checks; never point it at production. Fresh load still intentionally calls `/result` (409) and `/output-key`; 409 alone does not prove live AwaitingUser state.

Independent review verdict: PASS for a narrowly scoped PR, not release. Reviewer reran 28 helper tests, 22 Chromium fixtures and the targeted Rust auth/exchange test. Parent independently reran the helper/Chromium suites. The 343-pass workspace run was executed by the component reviewer, not independently repeated by the parent.

Remaining gaps: actual revised-browser passkey signing/completion and encrypted output recovery over the live service boundary, cross-surface enrollment, physical phone/mobile lifecycle, signed packaging/principal isolation, and mainnet are not claimed. HPKE success/decrypt-failure/ack-failure use real browser crypto with synthetic API/passkey fixtures. Add a future successful reload/recovery-after-ack-failure regression; this was a nonblocking review suggestion. No new physical ceremony was started, no GitHub write was made, and no production deployment occurred.
