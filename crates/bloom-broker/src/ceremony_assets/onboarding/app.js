'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  let bridge = null, activeReview = null, reviewTimer = null, reviewLoadTimer = null;
  const bridgeFragment = location.hash;
  const form = $('setup-form');
  const titles = ['How would you like to use Bloom?', 'Choose your apps', 'Finish setting up Bloom', 'Finish setting up Bloom', 'Setup complete'];
  let state = null, busy = false, hydrated = false, dirty = false, step = 0;
  let explicitPersona = false, policyApplied = false, sessionReady = false, chosenSetup = null;
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
  function updateSummary() {
    const config = state?.config ?? {};
    const persona = selected();
    const label = {custodian:'Institutional', trader:'Trader', degen:'Degen'}[persona] ?? persona;
    const ids = chosenSetup?.petals ?? config.petals ?? [];
    const names = ids.map(id => state?.catalog?.find(app => app.id === id)?.label ?? id);
    $('summary-persona').textContent = label;
    $('summary-apps').textContent = names.join(', ') || 'No apps selected';
    $('summary-approvals').textContent = persona === 'custodian' ?
      'One approval allows your selected apps. You will still approve every action.' :
      'First allow your apps, then enable automatic Polymarket buys. Other actions still ask for approval.';
    if (step === 4) $('summary-approvals').textContent = persona === 'custodian' ?
      'Automatic spending is off. Each wallet action still needs your approval.' :
      'Automatic Polymarket buy permissions are active. Other actions still ask for your approval.';
    $('setup-summary').hidden = step < 2;
  }
  function showApprovalStage(action, checking = false) {
    updateSummary();
    $('setup-content').hidden = true;
    $('review-host').hidden = false;
    $('review-loading').hidden = false; $('approval-retry').hidden = true;
    $('approval-title').hidden = false; $('approval-purpose').hidden = false;
    $('approval-progress').textContent = action === 'policy' ? `Approval 1 of ${selected() === 'custodian' ? 1 : 2}` : 'Approval 2 of 2';
    $('approval-title').textContent = action === 'policy' ? 'App access' : 'Automatic spending';
    $('approval-purpose').textContent = action === 'policy' ?
      'This signature allows your selected apps to request wallet actions. It does not move funds or enable automatic spending.' :
      'This separate signature enables automatic buys. Check which integration can act, how much it can spend, and when permission ends.';
    $('review-loading').textContent = checking ? 'Approval received. Checking it with Bloom…' : 'Preparing the exact permissions for your passkey approval…';
    $('setup-navigation').hidden = true;
    notice(checking ? 'Checking your approval…' : 'Preparing your approval…');
  }
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
    $('setup-navigation').hidden = step === 4 || !$('review-host').hidden;
    $('setup-diagnostics').hidden = step === 4;
    $('next').hidden = step >= 3;
    $('next').disabled = busy || !available || (step === 2 && !policyApplied);
    $('next').textContent = step === 1 ? 'Review and approve' : 'Continue';
    $('back').hidden = step === 0;
    $('session-explanation').textContent = custodian ? 'Institutional keeps each action under your review. No automatic persona session is requested.' : 'Use your passkey to approve the token allowances shown in the review.';
  }
  function showStep(next) {
    step = next;
    for (const section of document.querySelectorAll('[data-step]')) section.hidden = Number(section.dataset.step) !== step;
    $('panel-title').textContent = titles[step]; $('page-title').textContent = step < 2 ? (step === 0 ? 'Your preferences' : 'Limits and integrations') : `Wallet ${state?.selected_wallet ?? 'not selected'} · account 0`;
    $('step-label').textContent = step === 4 ? 'Complete' : `Step ${step + 1} of 4`;
    updateSummary();
    controls();
  }
  function closeReview(keepStage = false) {
    clearTimeout(reviewTimer); clearTimeout(reviewLoadTimer); reviewTimer = null; reviewLoadTimer = null; activeReview = null;
    $('ceremony-frame').hidden = true; $('ceremony-frame').removeAttribute('src');
    if (!keepStage) { $('review-host').hidden = true; $('setup-content').hidden = false; }
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
    if (data?.policy) return 'Your selected apps will appear in the passkey approval.';
    if (data?.state) return ({applied:'Selected apps approved.', awaiting_owner:'Waiting for your approval.', waiting_for_wallet:'Select an existing wallet first.', busy:'Another review is in progress.'})[data.state] ?? String(data.state).replaceAll('_', ' ');
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
    closeReview(true);
    showApprovalStage(action);
    activeReview = {action, wallet, preset, id:session.ceremony_id};
    url.search = 'onboarding=1';
    $('ceremony-frame').src = url.href;
    $('ceremony-page').hidden = false;
    const loadingReview = activeReview;
    reviewLoadTimer = setTimeout(() => {
      if (activeReview !== loadingReview || !$('ceremony-frame').hidden) return;
      $('review-loading').hidden = true; $('approval-retry').hidden = false;
      notice('The approval could not be loaded. Try again to check its status.', true);
    }, 15000);
    reviewTimer = setTimeout(() => { closeReview(); notice('This approval expired. Resume the review to try again.', true); }, Math.min(Number(session.expires_at_ms) - Date.now(), 30 * 60 * 1000));
  }
  window.addEventListener('message', event => {
    const pending = activeReview;
    if (!pending || event.origin !== location.origin || event.source !== $('ceremony-frame').contentWindow ||
        event.data?.type !== 'bloom.onboarding.ceremony' || event.data.ceremony_id !== pending.id ||
        pending.wallet !== state?.selected_wallet || pending.preset !== selected()) return;
    if (event.data.state === 'ready') {
      clearTimeout(reviewLoadTimer); $('approval-retry').hidden = true;
      $('approval-title').hidden = true; $('approval-purpose').hidden = true;
      $('ceremony-frame').hidden = false; $('review-loading').hidden = true;
      notice('Review the permissions below, then approve with your passkey.');
      fitReview();
      return;
    }
    if (event.data.state === 'failed') {
      clearTimeout(reviewLoadTimer); $('ceremony-frame').hidden = false;
      $('review-loading').hidden = true; $('approval-retry').hidden = false;
      notice('This approval could not be loaded. Read the error below or try again.', true);
      fitReview(); return;
    }
    if (event.data.state === 'canceled') { closeReview(); notice('This review was cancelled.'); return; }
    if (event.data.state !== 'completed') return;
    // A renderer notification is only a wake-up hint. The original Machine
    // action checks the authenticated Broker state and alone gates advancement.
    perform(async () => {
      if (activeReview !== pending) return;
      closeReview(true);
      showApprovalStage(pending.action, true);
      await runAction(pending.action, {checking:true});
    });
  });
  $('ceremony-frame').addEventListener('load', () => {
    if (!activeReview) return;
    const frame = $('ceremony-frame');
    const doc = frame.contentDocument;
    if (!doc || !frame.getAttribute('src') || doc.location?.pathname === 'blank') return;
    const observer = new ResizeObserver(fitReview); observer.observe(doc.body); fitReview();
    frame.contentWindow.addEventListener('pagehide', () => observer.disconnect(), {once:true});
  });
  function fitReview() {
    const frame = $('ceremony-frame'), doc = frame.contentDocument;
    if (doc?.body) frame.style.height = `${Math.ceil(doc.body.getBoundingClientRect().height) + 1}px`;
  }
  function render(data) {
    if (state && state.selected_wallet !== data.selected_wallet) resetWalletReview();
    state = data; const config = data.config ?? {};
    walletChoices(data);
    $('raw-state').textContent = display(data);
    $('policy-status').textContent = statusText(data.policy, 'Approve the apps you selected with your passkey.');
    $('session-status').textContent = statusText(data.sessions, 'No persona sessions reported.');
    if (!hydrated && !dirty) {
      const persona = typeof config.persona === 'string' ? {preset: config.persona} : config.persona;
      $('legacy-note').hidden = !config.setup_complete || !!persona;
      if (persona) {
        const radio = [...form.querySelectorAll('[name="persona"]')].find((input) => input.value === persona.preset);
        if (radio) radio.checked = true;

      }
      const saved = Array.isArray(config.petals) ? config.petals : [];
      renderPetals(data.catalog ?? [], saved.length || config.setup_complete ? saved : ['polymarket', 'hyperliquid']);
      hydrated = true;
    }
    if (data.machine?.persona_supported === false) notice('This Bloom installation needs updated services before persona permissions can be configured. Your existing wallets are unchanged.', true);
    else if (data.machine?.error) notice(display(data.machine.error), true);
    else if (!data.machine?.available) notice('Local Machine service unavailable. Start or reconnect it, then refresh. Your setup can be resumed.', true);
    else if (step < 2 && $('review-host').hidden) notice('Choose how you want to use Bloom.');
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
    }
    controls();
  });
  form.addEventListener('submit', (event) => event.preventDefault());
  $('back').addEventListener('click', () => showStep(Math.max(0, step - 1)));
  $('next').addEventListener('click', () => {
    if (!state?.selected_wallet || !state?.machine?.available) { notice('Select an available existing Bloom wallet before continuing.', true); return; }
    if (step === 2 && !policyApplied) { notice('Approve your selected apps before continuing.', true); return; }
    if (step !== 1) { showStep(step + 1); return; }
    if (!form.reportValidity()) return;
    if (state?.config?.setup_complete && !state.config.persona && !explicitPersona) { notice('Choose a persona explicitly before changing legacy preferences.', true); showStep(0); return; }
    const payload = {persona: selected(), petals: [...form.querySelectorAll('[name="petals"]:checked')].map((input) => input.value)};
    chosenSetup = payload;
    perform(async () => { resetWalletReview(); showStep(2); showApprovalStage('policy'); notice('Saving your choices…'); const result = await api('setup', payload); activity(result.stdout || display(result)); dirty = false; hydrated = false; await refresh(); showStep(2); await runAction('policy'); });
  });
  async function runAction(action, {checking = false} = {}) {
    if (!['policy', 'activate', 'stop', 'refresh'].includes(action)) throw new Error('Unknown setup action.');
    if (action === 'stop') { closeReview(); sessionReady = false; }
    if (action === 'policy' || action === 'activate') showApprovalStage(action, checking);
    else notice('Working with your local Bloom…');
    const result = await api('action', {action});
    activity(result.stdout || display(result.data ?? result));
    if (action === 'policy') policyApplied = result.data?.state === 'applied' || (result.data?.state === 'nothing_to_allow' && !(state?.config?.petals?.length));
    await refresh();
    if (result.ceremony_url) { await review(result, action); return; }
    if (action === 'policy') {
      if (policyApplied) {
        if (selected() === 'custodian') completeSetup();
        else { showStep(3); await runAction('activate'); }
      } else if (result.data?.state === 'awaiting_owner') {
        throw new Error('The passkey approval could not be opened. Reconnect setup and try again.');
      } else if (result.data?.state === 'busy') { closeReview(); notice('Another approval is being prepared. Try again in a moment.', true); }
      else if (result.data?.state === 'nothing_to_allow') { closeReview(); notice('No installed apps match your selection. Go back and choose an installed app.', true); }
      else { closeReview(); notice('Your wallet is not ready for approval. Refresh and try again.', true); }
    }
    if (action === 'activate') {
      const scopes = result.data;
      if (Array.isArray(scopes) && scopes.length && scopes.every(scope => !scope.locally_disabled && !scope.preparation_pending && scope.authority?.state === 'ACTIVE')) {
        sessionReady = true; controls(); if (policyApplied) completeSetup(); else notice('Your persona permissions are active.');
      } else { closeReview(); notice('Your spending permission is not active yet. Try the approval again or check the details.', true); }
    }
  }
  for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click', () => perform(() => runAction(button.dataset.action)));
  function completeSetup() {
    if (!policyApplied || (!sessionReady && selected() !== 'custodian') || !state?.machine?.available || !state?.selected_wallet) return;
    try { window.sessionStorage.removeItem("bloom.wallet.setup." + state.selected_wallet); } catch (_) {}
    closeReview();
    showStep(4);
    notice(selected() === 'custodian' ? 'Your setup is complete. Each action needs your approval.' : 'Your setup is complete. Your spending permissions are active.');
  }
  $('approval-retry').addEventListener('click', () => {
    const action = activeReview?.action;
    if (action) perform(async () => { closeReview(true); await runAction(action); });
  });
  $('finish').addEventListener('click', () => { if (!busy) completeSetup(); });
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
