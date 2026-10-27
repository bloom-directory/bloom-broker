'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  let bridge = null, activeReview = null, reviewTimer = null;
  const bridgeFragment = location.hash;
  const form = $('setup-form');
  const titles = ['How would you like to use Bloom?', 'Choose your limits and Petals', 'Review your wallet policy', 'Review session permissions', 'Setup complete'];
  const presets = {trader: ['100', '1000', '86400'], degen: ['1000', '10000', '604800']};
  let state = null, busy = false, hydrated = false, dirty = false, step = 0;
  let explicitPersona = false, policyApplied = false, sessionReady = false;
  const selected = () => form.elements.persona.value;
  const display = (value) => typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2);
  function renderPetals(catalog, selectedIds) {
    $('petal-choices').replaceChildren();
    for (const {id, label: name} of catalog) {
      const label = document.createElement('label'); label.className = 'choice';
      const input = document.createElement('input'); input.type = 'checkbox'; input.name = 'petals'; input.value = id;
      input.checked = selectedIds.includes(id);
      const text = document.createElement('span'); text.textContent = name;
      label.append(input, text); $('petal-choices').append(label);
    }
  }
  function notice(message, error = false) {
    $('status').textContent = message; $('status').classList.toggle('expired', error);
  }
  function activity(message) { $('activity').textContent = `${new Date().toLocaleTimeString()}  ${message}\n\n${$('activity').textContent}`; }
  function controls() {
    for (const button of document.querySelectorAll('button')) button.disabled = busy;
    for (const input of form.querySelectorAll('input, select')) input.disabled = busy;
    const custodian = selected() === 'custodian';
    $('limits').hidden = custodian; $('custodian-note').hidden = !custodian;
    for (const input of $('limits').querySelectorAll('input, select')) input.disabled = busy || custodian;
    const available = !!state?.machine?.available && state?.machine?.persona_supported !== false && !!state?.selected_wallet;
    $('activate').hidden = custodian || sessionReady;
    $('finish').hidden = !custodian && !sessionReady;
    $('finish').disabled = busy || !available || !policyApplied;
    $('activate').disabled = busy || custodian || !available || !policyApplied;
    for (const button of document.querySelectorAll('[data-action="policy"], [data-action="stop"]')) button.disabled = busy || !available;
    $('setup-navigation').hidden = step === 4;
    $('setup-diagnostics').hidden = step === 4;
    $('next').hidden = step >= 3;
    $('next').disabled = busy || !available || (step === 2 && !policyApplied);
    $('next').textContent = step === 1 ? 'Save and continue' : 'Next';
    $('back').hidden = step === 0;
    $('session-explanation').textContent = custodian ? 'Custodian keeps each action under your review. No automatic persona session is requested.' : 'Request bounded permissions after the wallet policy is applied. Each scope may need a separate approval.';
  }
  function showStep(next) {
    step = next;
    for (const section of document.querySelectorAll('[data-step]')) section.hidden = Number(section.dataset.step) !== step;
    $('panel-title').textContent = titles[step]; $('page-title').textContent = step < 2 ? (step === 0 ? 'Your preferences' : 'Limits and integrations') : `Wallet ${state?.selected_wallet ?? 'not selected'} · account 0`;
    $('step-label').textContent = step === 4 ? 'Complete' : `Step ${step + 1} of 4`;
    controls();
  }
  function closeReview() {
    clearTimeout(reviewTimer); reviewTimer = null; activeReview = null;
    $('review-host').hidden = true; $('ceremony-frame').removeAttribute('src');
    $('ceremony-page').hidden = false;
  }
  function resetWalletReview() {
    closeReview(); policyApplied = false; sessionReady = false;
  }
  function walletChoices(data) {
    $('wallet-choices').replaceChildren();
    const choices = data.wallet_choices ?? [];
    $('wallet-message').textContent = !choices.length ? 'No Bloom wallet was found in this installation. Open persona setup from your existing Bloom installation.' : data.selected_wallet ? `Existing wallet: ${data.selected_wallet}` : 'Choose an existing wallet to continue.';
    if (choices.length < 2) return;
    for (const wallet of choices) {
      const label = document.createElement('label'); label.className = 'choice';
      const input = document.createElement('input'); input.type = 'radio'; input.name = 'existing-wallet'; input.value = wallet.id; input.checked = wallet.id === data.selected_wallet;
      const text = document.createElement('span'); text.textContent = [wallet.id, wallet.address, wallet.kind].filter(Boolean).join(' · ');
      input.addEventListener('change', () => perform(async () => { resetWalletReview(); await api('action', {action:'select_wallet', wallet:wallet.id}); await refresh(); }));
      label.append(input, text); $('wallet-choices').append(label);
    }
  }
  function statusText(result, fallback) {
    if (!result) return fallback;
    if (result.error) return `Needs attention: ${display(result.error)}`;
    if (result.available === false) return 'Local service unavailable. Reconnect and refresh.';
    const data = result.data;
    if (Array.isArray(data)) return data.length ? data.map(item => `${item.persona ?? item.name ?? 'Session'} · ${item.locally_disabled ? 'Stopped' : item.preparation_pending ? 'Awaiting preparation' : item.authority?.state ?? item.status ?? item.state ?? 'Pending'}`).join('\n') : fallback;
    if (data?.policy) return 'Your wallet policy is available. Review or resume it to check the selected Petals.';
    if (data?.state) return ({applied:'Policy applied.', awaiting_owner:'Waiting for your approval.', waiting_for_wallet:'Select an existing wallet first.', busy:'Another review is in progress.'})[data.state] ?? String(data.state).replaceAll('_', ' ');
    if (result.stdout?.trim() && !result.stdout.trim().startsWith('{') && !result.stdout.trim().startsWith('[')) return result.stdout.trim().split('\n').map(line => line.split('\t').slice(0, 2).join(' · ')).join('\n');
    return fallback;
  }
  async function brokerApi(path, token, options = {}) {
    return fetch(path, {...options, headers: {'x-bloom-ceremony-token':token, ...(options.headers ?? {})}, credentials:'same-origin', redirect:'error', cache:'no-store', referrerPolicy:'no-referrer'});
  }
  async function review(result, action) {
    const url = new URL(result.ceremony_url);
    // The Machine validates this authority too. Normalize the two loopback
    // spellings to the Broker origin so the passkey frame is always same-origin.
    if (url.hostname === '127.0.0.1' && location.hostname === 'localhost' && url.port === location.port) url.hostname = 'localhost';
    const match = /^\/ceremony\/([A-Za-z0-9_-]{43})$/.exec(url.pathname);
    if (url.origin !== location.origin || url.username || url.password || url.search || url.hash || !match) throw new Error('Unexpected approval URL from the local service.');
    const wallet = state.selected_wallet, preset = selected();
    const response = await brokerApi('/api/session', match[1]);
    if (!response.ok) throw new Error('This approval expired. Resume the review to prepare it again.');
    const session = await response.json();
    if (!/^[0-9a-f]{64}$/.test(session.ceremony_id) || !Number.isFinite(Number(session.expires_at_ms)) || Number(session.expires_at_ms) <= Date.now()) throw new Error('This approval is unavailable or expired.');
    closeReview();
    activeReview = {action, wallet, preset, id:session.ceremony_id};
    url.search = 'onboarding=1';
    $('ceremony-frame').src = url.href;
    $('ceremony-page').hidden = true; $('review-host').hidden = false;
    reviewTimer = setTimeout(() => { closeReview(); notice('This approval expired. Resume the review to try again.', true); }, Math.min(Number(session.expires_at_ms) - Date.now(), 30 * 60 * 1000));
  }
  window.addEventListener('message', event => {
    const pending = activeReview;
    if (!pending || event.origin !== location.origin || event.source !== $('ceremony-frame').contentWindow ||
        event.data?.type !== 'bloom.onboarding.ceremony' || event.data.ceremony_id !== pending.id ||
        pending.wallet !== state?.selected_wallet || pending.preset !== selected()) return;
    if (event.data.state === 'canceled') { closeReview(); notice('This review was cancelled.'); return; }
    if (event.data.state !== 'completed') return;
    // A renderer notification is only a wake-up hint. The original Machine
    // action checks the authenticated Broker state and alone gates advancement.
    perform(async () => {
      if (activeReview !== pending) return;
      closeReview();
      await runAction(pending.action);
    });
  });
  $('ceremony-frame').addEventListener('load', () => {
    if (!activeReview) return;
    const frame = $('ceremony-frame');
    const doc = frame.contentDocument;
    if (!doc) return;
    const resize = () => { frame.style.height = `${Math.max(doc.documentElement.scrollHeight, window.innerHeight)}px`; };
    const observer = new ResizeObserver(resize); observer.observe(doc.body); resize();
    frame.contentWindow.addEventListener('pagehide', () => observer.disconnect(), {once:true});
  });
  function render(data) {
    if (state && state.selected_wallet !== data.selected_wallet) resetWalletReview();
    state = data; const config = data.config ?? {};
    walletChoices(data);
    $('raw-state').textContent = display(data);
    $('policy-status').textContent = statusText(data.policy, 'Policy has not yet been reported. Review or resume for the selected wallet.');
    $('session-status').textContent = statusText(data.sessions, 'No persona sessions reported.');
    if (!hydrated && !dirty) {
      const persona = typeof config.persona === 'string' ? {preset: config.persona} : config.persona;
      $('legacy-note').hidden = !config.setup_complete || !!persona;
      if (persona) {
        const radio = [...form.querySelectorAll('[name="persona"]')].find((input) => input.value === persona.preset);
        if (radio) radio.checked = true;
        const action = config.persona_limits?.per_action_usd;
        const daily = config.persona_limits?.daily_usd;
        if (action !== null && action !== undefined) $('per-action').value = action;
        if (daily !== null && daily !== undefined) $('daily').value = daily;
        if (config.persona_limits?.session_duration_secs != null) { const savedDuration = config.persona_limits.session_duration_secs; if (![...$('duration').options].some(option => option.value === savedDuration)) $('duration').add(new Option(`${savedDuration} seconds (saved)`, savedDuration)); $('duration').value = savedDuration; }
        if (persona.preset !== 'custodian' && (action == null || daily == null)) {
          $('per-action').value = ''; $('daily').value = '';
          notice('Existing limits need an exact decimal representation. Enter the intended amounts explicitly before saving.', true);
        }
      }
      const saved = Array.isArray(config.petals) ? config.petals : [];
      renderPetals(data.catalog ?? [], saved.length || config.setup_complete ? saved : ['polymarket', 'hyperliquid']);
      hydrated = true;
    }
    if (data.machine?.persona_supported === false) notice('This Bloom installation needs updated services before persona permissions can be configured. Your existing wallets are unchanged.', true);
    else if (data.machine?.error) notice(display(data.machine.error), true);
    else if (!data.machine?.available) notice('Local Machine service unavailable. Start or reconnect it, then refresh. Your setup can be resumed.', true);
    else notice(config.setup_complete ? 'Preferences saved. Continue or resume the wallet reviews below.' : 'Choose your preferences to begin.');
    if (!(data.wallet_choices ?? []).length) notice('No Bloom wallet was found in this installation. Open persona setup from your existing Bloom installation.', true);
    showStep(step);
  }
  async function api(path, payload) {
    const response = await fetch(new URL(`api/${path}`, bridge), {method: payload === undefined ? 'GET' : 'POST', headers: {'Accept':'application/json', ...(payload === undefined ? {} : {'Content-Type':'application/json'})}, ...(payload === undefined ? {} : {body: JSON.stringify(payload)}), cache:'no-store', credentials:'omit', redirect:'error', referrerPolicy:'no-referrer'});
    const text = await response.text(); let data;
    try { data = JSON.parse(text); } catch { throw new Error(text || `Local service returned HTTP ${response.status}`); }
    if (!response.ok || data.error || (data.exit_code != null && data.exit_code !== 0)) throw new Error(display(data.error ?? data.stderr ?? data.stdout ?? data));
    return data;
  }
  async function refresh() { render(await api('state')); }
  async function perform(task) {
    if (busy) return; busy = true; controls();
    try { await task(); } catch (error) { closeReview(); notice(error.message, true); activity(`Error: ${error.message}`); }
    finally { busy = false; controls(); }
  }
  for (const radio of form.querySelectorAll('[name="persona"]')) radio.addEventListener('click', () => { explicitPersona = true; });
  form.addEventListener('input', () => { dirty = true; });
  form.addEventListener('change', (event) => {
    dirty = true;
    if (event.target.name === 'persona') {
      explicitPersona = true;
      if (presets[selected()]) [$('per-action').value, $('daily').value, $('duration').value] = presets[selected()];
    }
    controls();
  });
  form.addEventListener('submit', (event) => event.preventDefault());
  $('back').addEventListener('click', () => showStep(Math.max(0, step - 1)));
  $('next').addEventListener('click', () => {
    if (!state?.selected_wallet || !state?.machine?.available) { notice('Select an available existing Bloom wallet before continuing.', true); return; }
    if (step === 2 && !policyApplied) { notice('Complete the policy review before continuing.', true); return; }
    if (step !== 1) { showStep(step + 1); return; }
    if (!form.reportValidity()) return;
    if (state?.config?.setup_complete && !state.config.persona && !explicitPersona) { notice('Choose a persona explicitly before changing legacy preferences.', true); showStep(0); return; }
    const payload = {persona: selected(), petals: [...form.querySelectorAll('[name="petals"]:checked')].map((input) => input.value)};
    if (selected() !== 'custodian') Object.assign(payload, {per_action_usd:$('per-action').value.trim(), daily_usd:$('daily').value.trim(), ...(Number.isSafeInteger(Number($('duration').value)) ? {session_duration_secs:Number($('duration').value)} : {})});
    perform(async () => { resetWalletReview(); notice('Saving persona preferences…'); const result = await api('setup', payload); activity(result.stdout || display(result)); dirty = false; hydrated = false; await refresh(); showStep(2); await runAction('policy'); });
  });
  async function runAction(action) {
    if (!['policy', 'activate', 'stop', 'refresh'].includes(action)) throw new Error('Unknown setup action.');
    if (action === 'stop') { closeReview(); sessionReady = false; }
    notice('Working with your local Bloom…');
    const result = await api('action', {action});
    activity(result.stdout || display(result.data ?? result));
    if (action === 'policy') policyApplied = result.data?.state === 'applied' || (result.data?.state === 'nothing_to_allow' && !(state?.config?.petals?.length));
    await refresh();
    if (result.ceremony_url) { await review(result, action); return; }
    if (action === 'policy' && policyApplied) { showStep(3); notice('Wallet policy applied. Continue with your session permissions.'); }
    if (action === 'activate') {
      const scopes = result.data;
      if (Array.isArray(scopes) && scopes.length && scopes.every(scope => !scope.locally_disabled && !scope.preparation_pending && scope.authority?.state === 'ACTIVE')) {
        sessionReady = true; controls(); notice('Your persona permissions are active. Setup is complete.');
      } else notice('No active automatic session was confirmed. Check the session details below before continuing.', true);
    }
  }
  for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click', () => perform(() => runAction(button.dataset.action)));
  $('finish').addEventListener('click', () => {
    if (busy || !policyApplied || (!sessionReady && selected() !== 'custodian') || !state?.machine?.available || !state?.selected_wallet) return;
    try { window.sessionStorage.removeItem("bloom.wallet.setup." + state.selected_wallet); } catch (_) {}
    showStep(4);
    notice(selected() === 'custodian' ? 'Each action remains under your review.' : 'Your persona permissions are active.');
  });
  showStep(0);
  try {
    const storageKey = 'bloom.onboarding.bridge.v1';
    const lifetime = 30 * 60 * 1000;
    let storage;
    try { storage = window.sessionStorage; } catch (_) { /* Retain the fragment if tab storage is unavailable. */ }
    let connection;
    if (bridgeFragment) {
      // An explicit new connection replaces the old one, including on failure.
      try { storage?.removeItem(storageKey); } catch (_) {}
      const params = new URLSearchParams(bridgeFragment.slice(1));
      const raw = params.get('bridge');
      if ([...params.keys()].length !== 1 || !raw) throw new Error('Invalid setup link. Reopen the link printed by Bloom.');
      connection = {url:raw, expires_at:Date.now() + lifetime};
    } else {
      try { connection = JSON.parse(storage?.getItem(storageKey) ?? 'null'); } catch (_) {}
      if (!connection) throw new Error('Reopen the setup link printed by Bloom to reconnect this page.');
    }
    if (!Number.isFinite(connection.expires_at) || connection.expires_at <= Date.now() || connection.expires_at > Date.now() + lifetime) {
      try { storage?.removeItem(storageKey); } catch (_) {}
      throw new Error('This setup connection expired. Run bloom onboard to reconnect.');
    }
    const url = new URL(connection.url);
    if (url.href !== connection.url || url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.search || url.hash || !/^\/onboarding\/[0-9a-f]{64}\/$/.test(url.pathname)) {
      try { storage?.removeItem(storageKey); } catch (_) {}
      throw new Error('Invalid local setup connection. Reopen the link printed by Bloom.');
    }
    // Tab-scoped recovery only; never localStorage, cookies, or passkey data.
    // Reload preserves the original deadline. Machine independently enforces
    // its shorter idle timeout and absolute process lifetime on every request.
    try {
      if (storage) {
        storage.setItem(storageKey, JSON.stringify(connection));
        history.replaceState(null, '', '/onboarding/');
      }
    } catch (_) { /* A valid launch fragment remains usable on reload. */ }
    bridge = url;
    perform(refresh);
  } catch (error) { notice(error.message, true); }
})();
