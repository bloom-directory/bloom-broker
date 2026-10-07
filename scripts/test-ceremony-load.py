#!/usr/bin/env python3
"""Real Chromium, unmodified shipped HTML/JS, synthetic API; no wallet operations.
Setup: uv venv .venv; uv pip install --python .venv/bin/python playwright==1.63.0
       .venv/bin/python -m playwright install chromium
Run:   .venv/bin/python scripts/test-ceremony-load.py [--baseline] [--latency-ms 200]
--baseline reads exact pre-change JS from git for comparative measurement.
Injected API delay is not a phone/relay performance claim. Browser dependencies
must be available (playwright install-deps chromium on a disposable test host).
"""
import argparse
import asyncio
import json
from pathlib import Path
import subprocess
from urllib.parse import urlparse
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'crates/bloom-broker/src/ceremony_assets'
BASE = '5095af43ad22994cb0a0bdad07a1d7adcf2410eb'
ID = 'a' * 64
CSRF = 'b' * 43
ORIGIN = 'https://ceremony.invalid'


async def check(browser, app, baseline, latency, case='fresh'):
    context = await browser.new_context()
    page = await context.new_page()
    calls, errors = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    result_entered, release_result = asyncio.Event(), asyncio.Event()
    projection = {'ceremony_id': ID, 'ceremony_kind': 'sealed_approval',
                  'expires_at_ms': 0,
                  'challenges': [{'challenge': 'AA', 'binding': {}}],
                  'webauthn_options': {'allowed_credentials': []},
                  'signer_contribution': {},
                  'review_manifest': {'canonical_plan': 'Synthetic exact-byte review'}}
    output_case = case in ('terminal-output-failure', 'terminal-ack-failure', 'output-success')
    if output_case:
        projection['ceremony_kind'] = 'wallet_export'
        projection['signer_contribution'] = {
            'ceremony_id': ID, 'ceremony_kind': 'wallet_export',
            'custody_operation_id': 'e' * 64}
        projection['challenges'][0]['binding'] = {
            'exact_terms_digest': 'f' * 64, 'signer_contribution_digest': '1' * 64}
    reloading = False

    async def route(request):
        path = urlparse(request.request.url).path
        if path.startswith('/api/'):
            calls.append(path)
            await asyncio.sleep(latency / 1000)
            if path == '/api/session/exchange':
                projection['expires_at_ms'] = await page.evaluate('Date.now() + 60000')
                if case == 'expired':
                    projection['expires_at_ms'] = await page.evaluate('Date.now() - 1')
                payload = {'ceremony_id': ID, 'csrf': CSRF, 'session': projection}
                if case == 'older-server':
                    del payload['session']
                if case == 'identity-mismatch':
                    projection['ceremony_id'] = 'd' * 64
                status = 200
            elif path == f'/api/session/{ID}':
                payload, status = projection, 200
            elif path == f'/api/session/{ID}/result':
                result_entered.set()
                if case == 'held-result':
                    await release_result.wait()
                payload, status = {}, 409
                if case == 'result-failure':
                    status = 503
                if case == 'completed' or (reloading and case == 'reload-completed'):
                    payload, status = {'receipt_digest': 'synthetic-receipt'}, 200
            elif path == f'/api/session/{ID}/output-key':
                payload, status = projection, 200
            elif path == f'/api/session/{ID}/cancel':
                payload, status = {}, 200
            elif path == f'/api/session/{ID}/complete':
                payload, status = {}, 403
                if output_case:
                    # Actual HPKE and IndexedDB recipient; only the failure
                    # fixture deliberately authenticates different AAD.
                    envelope = await page.evaluate('''async ({fail, session}) => {
                      const contribution = session.signer_contribution;
                      const aad = canonicalJson({ceremony_id: contribution.ceremony_id,
                        ceremony_kind: contribution.ceremony_kind,
                        custody_operation_id: contribution.custody_operation_id,
                        public_binding_digest: session.challenges[0].binding.exact_terms_digest,
                        signer_contribution_digest: session.challenges[0].binding.signer_contribution_digest});
                      return hpkeSeal(outputRecipient.publicKey, te.encode('bloom-custody-output/v1'),
                        te.encode(fail ? 'wrong-aad' : aad), te.encode('synthetic-test-output'));
                    }''', {'fail': case == 'terminal-output-failure', 'session': projection})
                    payload, status = {'encrypted_browser_result': envelope}, 200
            elif path == f'/api/session/{ID}/ack':
                payload, status = {}, 503 if case == 'terminal-ack-failure' else 200
            else:
                raise AssertionError(f'unexpected API {path}')
            await request.fulfill(status=status, json=payload)
        elif path.endswith('app.js'):
            await request.fulfill(content_type='application/javascript', body=app)
        elif path.endswith('style.css'):
            await request.fulfill(content_type='text/css', body=(ASSETS / 'style.css').read_text())
        elif path.endswith('.svg'):
            await request.fulfill(content_type='image/svg+xml', body=(ASSETS / 'bloom-primary.svg').read_text())
        else:
            await request.fulfill(content_type='text/html', body=(ASSETS / 'index.html').read_text())

    await page.route('**/*', route)
    await page.add_init_script('''
      window.readyAt = null;
      new MutationObserver(() => {
        const button = document.getElementById('approve');
        if (button && !button.disabled && window.readyAt === null)
          window.readyAt = performance.now();
      }).observe(document, {subtree:true, attributes:true, childList:true});
    ''')
    if case in ('failed-crypto', 'held-crypto'):
        await page.add_init_script('''
          const generate = crypto.subtle.generateKey.bind(crypto.subtle);
          const gate = new Promise(resolve => window.releaseCrypto = resolve);
          crypto.subtle.generateKey = async (...args) => {
            window.cryptoEntered = true;
            await gate;
            return generate(...args);
          };
        ''' if case == 'held-crypto' else '''
          crypto.subtle.generateKey = async () => { throw new Error('injected crypto failure'); };
        ''')
    if case == 'held-storage':
        await page.add_init_script('''
          const open = indexedDB.open.bind(indexedDB);
          indexedDB.open = (...args) => {
            const request = open(...args);
            Object.defineProperty(request, 'onsuccess', {set(handler) {
              request.addEventListener('success', event => {
                window.releaseStorage = () => handler.call(request, event);
              }, {once:true});
            }});
            return request;
          };
        ''')
    await page.goto(ORIGIN + '/ceremony/#cap=' + 'c' * 43)
    if case in ('held-crypto', 'held-storage', 'held-result'):
        if case == 'held-result':
            await asyncio.wait_for(result_entered.wait(), 10)
        else:
            await page.wait_for_function('window.cryptoEntered' if case == 'held-crypto'
                                         else 'typeof window.releaseStorage === "function"')
        await page.wait_for_timeout(latency * 3 + 100)
        assert await page.evaluate('window.readyAt === null'), case
        assert await page.locator('#approve').is_disabled(), case
        if case != 'held-result':
            assert calls == [], calls
            await page.evaluate('window.releaseCrypto()' if case == 'held-crypto'
                                else 'window.releaseStorage()')
        else:
            release_result.set()

    blocked = case in ('expired', 'failed-crypto', 'identity-mismatch', 'result-failure')
    if blocked or case == 'completed':
        if blocked:
            await page.wait_for_function('document.getElementById("ceremony-page").classList.contains("link-unavailable")')
        else:
            await page.wait_for_function('document.getElementById("status").textContent === "Completed."')
        await page.wait_for_timeout(100)
        assert await page.evaluate('window.readyAt === null'), f'{case} enabled Approve'
        assert await page.locator('#approve').is_disabled()
        if case == 'failed-crypto':
            assert not calls, calls
        if case == 'completed':
            await page.evaluate('reportApprovalFailure(new Error("late failure"))')
            assert await page.locator('#approve').is_disabled(), 'Completed flow re-enabled Approve'
    else:
        await page.wait_for_function('window.readyAt !== null')
        elapsed = await page.evaluate('window.readyAt')
        expected_count = 3 if baseline or case == 'older-server' or output_case else 2
        assert len(calls) == expected_count, calls
        assert calls[-1].endswith('/output-key' if output_case else '/result'), calls
        stored = await page.evaluate('JSON.parse(sessionStorage.getItem("bloom.ceremony.remote-session.v1"))')
        assert set(stored) == {'ceremony_id', 'csrf', 'expires_at'}, stored
        if case == 'fresh':
            print(json.dumps({'case': case, 'baseline': baseline, 'latency_ms': latency,
                              'serial_api_calls': len(calls), 'ready_ms': round(elapsed, 1)}), flush=True)
        if case == 'throttled-expiry-click':
            await page.evaluate('''() => {
              clearInterval(expiryTimer);
              const now = Date.now(); Date.now = () => now + 120000;
              window.passkeyCalls = 0;
              navigator.credentials.get = async () => {
                window.passkeyCalls++; throw new Error('should never prompt');
              };
              document.getElementById('approve').click();
            }''')
            await page.wait_for_timeout(100)
            assert await page.evaluate('window.passkeyCalls === 0'), 'Expired click prompted'
            assert await page.locator('#approve').is_disabled()
        if case.startswith('late-') or case in ('throttled-expiry-success', 'throttled-expiry-failure') or output_case:
            await page.evaluate('''() => {
              navigator.credentials.get = () => new Promise((resolve, reject) => {
                window.rejectPasskey = () => reject(new Error('late rejection'));
                window.resolvePasskey = () => resolve({
                  rawId: new Uint8Array(1),
                  response: {authenticatorData: new Uint8Array(1),
                    clientDataJSON: new Uint8Array(1), signature: new Uint8Array(1)},
                  getClientExtensionResults: () => ({prf:{results:{first:new Uint8Array(32)}}})
                });
              });
            }''')
            await page.locator('#approve').click()
            await page.wait_for_function('typeof window.rejectPasskey === "function"')
            if output_case:
                await page.evaluate('window.resolvePasskey()')
                await page.wait_for_function('document.getElementById("approve").hidden')
                await page.wait_for_timeout(latency + 100)
                status = await page.locator('#status').text_content()
                if case == 'output-success':
                    assert status == 'Completed.', status
                else:
                    assert status != 'Completed.', 'Result decryption failure was silently presented as Completed.'
                    assert 'result' in status.lower(), status
                assert await page.locator('#approve').is_disabled()
                assert sum(path.endswith('/complete') for path in calls) == 1
                assert sum(path.endswith('/ack') for path in calls) == (0 if case == 'terminal-output-failure' else 1)
                saved = await page.evaluate('sessionStorage.getItem("bloom.ceremony.remote-session.v1") !== null')
                assert saved == (case != 'output-success')
                has_recipient = await page.evaluate('''async () => {
                  const db = await openBrowserState();
                  try { return Boolean(await requestResult(db.transaction(browserStateStore)
                    .objectStore(browserStateStore).get(ceremonyId))); }
                  finally { db.close(); }
                }''')
                assert has_recipient == (case != 'output-success')
                if case != 'terminal-output-failure':
                    assert 'synthetic-test-output' in await page.locator('#review').text_content()
                assert not errors, errors
                print(json.dumps({'case': case, 'passed': True, 'api_calls': len(calls)}), flush=True)
                await context.close()
                return
            elif case.startswith('throttled-expiry-'):
                await page.evaluate('''() => {
                  clearInterval(expiryTimer);
                  const now = Date.now(); Date.now = () => now + 120000;
                }''')
            elif case.startswith('late-expiry'):
                await page.evaluate('''() => {
                  const now = Date.now();
                  Date.now = () => now + 120000;
                }''')
                await page.wait_for_function('document.getElementById("status").textContent.includes("expired")')
            else:
                await page.locator('#cancel').click()
                await page.wait_for_function('document.getElementById("status").textContent.includes("Cancelled")')
            await page.evaluate('window.resolvePasskey()' if case.endswith('success') else 'window.rejectPasskey()')
            await page.wait_for_timeout(100)
            assert await page.locator('#approve').is_disabled(), f'{case} re-enabled Approve'
            assert not any(path.endswith('/complete') for path in calls)
        if case in ('reload', 'reload-completed'):
            reloading = True
            calls.clear()
            # A stale cached projection must never be used, even if injected.
            await page.evaluate('''() => {
              const key = 'bloom.ceremony.remote-session.v1';
              const saved = JSON.parse(sessionStorage.getItem(key));
              saved.session = {ceremony_id:'stale'};
              sessionStorage.setItem(key, JSON.stringify(saved));
            }''')
            await page.reload()
            if case == 'reload':
                await page.wait_for_function('window.readyAt !== null')
            else:
                await page.wait_for_function('document.getElementById("status").textContent === "Completed."')
                assert await page.evaluate('window.readyAt === null')
                assert await page.locator('#approve').is_disabled()
            assert calls == [f'/api/session/{ID}', f'/api/session/{ID}/result'], calls
    assert not errors, errors
    if case != 'fresh':
        print(json.dumps({'case': case, 'passed': True, 'api_calls': len(calls)}), flush=True)
    await context.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--latency-ms', type=int, default=200)
    parser.add_argument('--case', help='Run one named case instead of the full suite')
    args = parser.parse_args()
    app = (subprocess.check_output(['git', 'show', f'{BASE}:crates/bloom-broker/src/ceremony_assets/app.js'], cwd=ROOT).decode()
           if args.baseline else (ASSETS / 'app.js').read_text())
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            cases = ['fresh'] if args.baseline else [
                'terminal-output-failure', 'terminal-ack-failure', 'output-success',
                'throttled-expiry-failure', 'throttled-expiry-success', 'throttled-expiry-click',
                'late-expiry-success', 'late-cancel-success',
                'late-expiry-failure', 'late-cancel-failure',
                'fresh', 'expired', 'failed-crypto', 'held-crypto', 'held-storage',
                'held-result', 'completed', 'reload', 'reload-completed',
                'older-server', 'identity-mismatch', 'result-failure']
            if args.case:
                if args.case not in cases:
                    parser.error('unknown case')
                cases = [args.case]
            for case in cases:
                await check(browser, app, args.baseline, args.latency_ms, case)
        finally:
            await browser.close()


if __name__ == '__main__':
    asyncio.run(main())
