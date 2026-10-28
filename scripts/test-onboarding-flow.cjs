// Execute the shipped wizard in Node's VM with only the DOM surface it uses.
// No authority or passkey operation is simulated: assertions cover UI gating
// and the order of calls to the existing Machine reconciliation API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../crates/bloom-broker/src/ceremony_assets/onboarding/app.js'), 'utf8');
const baseState = {selected_wallet:'alice',wallet_choices:[{id:'alice'}],machine:{available:true},config:{exists:true,setup_complete:true,persona:{preset:'trader'},persona_limits:{window_secs:'86400'},petals:['polymarket']},catalog:[]};
function harness(actions, options = {}) {
  const expectedAction = options.action ?? 'policy';
  const pauseActions = options.pauseActions ?? [];
  const elements = new Map(), listeners = {}, calls = [], releases = new Map();
  let actionNumber = 0;
  function element() { return {hidden:false,value:'',options:[],style:{},dataset:{},handlers:{},classList:{toggle(){}},contentWindow:{},querySelectorAll:()=>[],addEventListener(name,fn){this.handlers[name]=fn;},append(){},replaceChildren(){},removeAttribute(name){delete this[name];},getAttribute(name){return this[name]??null;},add(option){this.options.push(option);}}; }
  const get = id => {if (!elements.has(id)) elements.set(id,element()); return elements.get(id);};
  get('review-host').hidden=true;get('ceremony-frame').hidden=true;
  get('setup-form').elements = {persona:{value:options.persona ?? (options.action ? 'trader' : 'custodian')}};
  const location = new URL('http://localhost:18734/onboarding/');
  location.hash = options.hash ?? ('#bridge=' + encodeURIComponent('http://127.0.0.1:54321/onboarding/'+'a'.repeat(64)+'/'));
  const storage = options.storage ?? new Map();
  const sessionStorage = options.storageUnavailable ? {getItem(){throw Error('storage unavailable');},setItem(){throw Error('storage unavailable');},removeItem(){throw Error('storage unavailable');}} : {getItem:key=>storage.get(key) ?? null,setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)};
  const response = (data,ok=true) => ({ok,status:ok?200:409,json:async()=>data,text:async()=>JSON.stringify(data)});
  let sessionCount = 0;
  const sandbox = {URL,URLSearchParams,Date,Number,JSON,Option:function(text,value){this.value=value;},location,history:{replaceState(){location.hash='';}},document:{getElementById:get,querySelectorAll:()=>[],createElement:element},window:{sessionStorage,addEventListener:(name,fn)=>{listeners[name]=fn;}},setTimeout:()=>1,clearTimeout(){},ResizeObserver:function(){},fetch:async(raw,options={})=>{
    const url = new URL(raw,location); calls.push({url:url.href,body:options.body});
    if (url.pathname.endsWith('/api/state')) return response(JSON.parse(JSON.stringify(baseState)));
    if (url.pathname.endsWith('/api/action')) {assert.equal(JSON.parse(options.body).action,Array.isArray(expectedAction)?expectedAction.shift():expectedAction); assert.ok(actions.length,'unexpected reconciliation');const data=actions.shift();const n=++actionNumber;if(pauseActions.includes(n))await new Promise(resolve=>releases.set(n,resolve));return response(data);}
    if (url.pathname === '/api/session') return response({ceremony_id:String(++sessionCount).repeat(64),expires_at_ms:Date.now()+60000});
    throw new Error('unexpected fetch '+url);
  }};
  vm.createContext(sandbox);
  vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.hooks={runAction,showStep,refresh,get step(){return step},get pending(){return activeReview}};})();'),sandbox);
  const settle = async()=>{for(let i=0;i<8;i++) await new Promise(resolve=>setImmediate(resolve));};
  const message = overrides => listeners.message({origin:location.origin,source:get('ceremony-frame').contentWindow,data:{type:'bloom.onboarding.ceremony',ceremony_id:sandbox.hooks.pending?.id,state:'completed'},...overrides});
  return {hooks:sandbox.hooks,calls,message,settle,get,storage,location,release:n=>releases.get(n)()};
}
const pending = token => ({ceremony_url:'http://localhost:18734/ceremony/'+token.repeat(43),data:{state:'awaiting_owner'}});
(async()=>{
  const connected=harness([]);await connected.settle();
  const reloaded=harness([],{hash:'',storage:connected.storage});await reloaded.settle();
  assert.ok(reloaded.calls.some(call=>new URL(call.url).pathname.endsWith('/api/state')), 'reload must rediscover existing wallets');
  assert.equal(reloaded.get('next').disabled,false);
  const unavailable=harness([],{storageUnavailable:true});await unavailable.settle();assert.ok(unavailable.location.hash.startsWith('#bridge='));assert.ok(unavailable.calls.some(call=>new URL(call.url).pathname.endsWith('/api/state')));
  const key='bloom.onboarding.bridge.v1';
  const expires=JSON.parse(connected.storage.get(key)).expires_at;
  assert.equal(JSON.parse(reloaded.storage.get(key)).expires_at,expires,'reload cannot extend the stored connection lifetime');
  for (const cached of [
    {url:'http://127.0.0.1:54321/onboarding/'+'a'.repeat(64)+'/',expires_at:Date.now()-1},
    {url:'https://attacker.example/onboarding/'+'a'.repeat(64)+'/',expires_at:Date.now()+60000}
  ]) {
    const invalid=harness([],{hash:'',storage:new Map([[key,JSON.stringify(cached)]])});await invalid.settle();assert.equal(invalid.calls.length,0);assert.equal(invalid.get('next').disabled,true);
  }
  const malformed=harness([],{hash:'#bridge=https://attacker.example/',storage:connected.storage});await malformed.settle();assert.equal(malformed.calls.length,0,'an invalid new fragment cannot fall back to a cached connection');

  // DefaultPolicyStatus uses #[serde(tag = "state")]; use the real wire shape.
  const resumed = harness([{data:{state:'applied',petals:['polymarket']}}]); await resumed.settle(); resumed.hooks.showStep(2); await resumed.hooks.runAction('policy'); assert.equal(resumed.hooks.step,4); assert.equal(resumed.get('activate').hidden,true); assert.equal(resumed.hooks.pending,null);
  // ApprovalLifecycleState is serialized in SCREAMING_SNAKE_CASE by the API.
  const activeScope = {authority:{state:'ACTIVE'},locally_disabled:false,preparation_pending:false};
  const activated = harness([{data:[activeScope,activeScope]}],{action:'activate'});await activated.settle();await activated.hooks.runAction('activate');
  assert.equal(activated.get('activate').hidden,true,'confirmed active sessions must hide the activation button');
  assert.equal(activated.get('finish').hidden,false);
  assert.match(activated.get('status').textContent,/permissions are active/);
  // Finish must visibly leave the wizard and must not create another approval.
  activated.get('finish').handlers.click();
  assert.equal(activated.hooks.step,0,'session confirmation alone cannot bypass the wallet-policy gate');
  const finished=harness([{data:{state:'applied',petals:['polymarket']}}]);await finished.settle();await finished.hooks.runAction('policy');
  finished.get('setup-form').elements.persona.value='custodian';
  const callsBeforeFinish=finished.calls.length;finished.get('finish').handlers.click();
  assert.equal(finished.hooks.step,4);assert.equal(finished.get('panel-title').textContent,'Setup complete');
  assert.equal(finished.get('setup-navigation').hidden,true);assert.equal(finished.get('setup-diagnostics').hidden,true);
  assert.equal(finished.calls.length,callsBeforeFinish,'finishing cannot request more authority');
  const degenFinished=harness([{data:{state:'applied',petals:['polymarket']}},{data:[activeScope]}],{action:['policy','activate']});
  await degenFinished.settle();await degenFinished.hooks.runAction('policy');
  const degenCalls=degenFinished.calls.length;degenFinished.get('finish').handlers.click();
  assert.equal(degenFinished.hooks.step,4);assert.equal(degenFinished.calls.length,degenCalls);
  const html=fs.readFileSync(path.join(__dirname,'../crates/bloom-broker/src/ceremony_assets/onboarding/index.html'),'utf8');
  assert.ok(!html.includes('session-selection'),'normal onboarding must not require developer selection files');

  for (const scopes of [[],[activeScope,{...activeScope,authority:{state:'AWAITING_CEREMONY'}}],[{...activeScope,locally_disabled:true}],[{...activeScope,preparation_pending:true}]]) {
    const inactive=harness([{data:scopes}],{action:'activate'});await inactive.settle();await inactive.hooks.runAction('activate');
    assert.equal(inactive.get('activate').hidden,false);assert.equal(inactive.get('finish').hidden,true);
  }
  const h = harness([pending('b'),{data:{state:'applied',petals:['polymarket']}}]); await h.settle(); h.hooks.showStep(2); await h.hooks.runAction('policy');
  const loadFailed=harness([pending('l')]);await loadFailed.settle();loadFailed.hooks.showStep(2);await loadFailed.hooks.runAction('policy');
  loadFailed.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:loadFailed.hooks.pending.id,state:'failed'}});await loadFailed.settle();
  assert.equal(loadFailed.hooks.step,2);assert.equal(loadFailed.get('approval-retry').hidden,false);assert.match(loadFailed.get('status').textContent,/could not be loaded/);
  const before=h.calls.length;
  assert.equal(h.get('ceremony-frame').hidden,true,'HTML load alone must not reveal a half-loaded review');
  h.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:h.hooks.pending.id,state:'ready'}});await h.settle();
  assert.equal(h.get('ceremony-frame').hidden,false);assert.equal(h.hooks.step,2,'ready is display-only and cannot authorize progression');

  h.message({origin:'https://attacker.example'}); h.message({source:{}}); h.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:'f'.repeat(64),state:'completed'}}); await h.settle();
  assert.equal(h.calls.length,before); assert.equal(h.hooks.step,2);
  h.message(); await h.settle(); assert.equal(h.hooks.step,4);
  assert.equal(h.calls.filter(c=>c.body).length,2);
  for (const result of [{data:{state:'awaiting_owner'}},{data:{state:'busy'}},{error:'Reconciliation rejected'}]) {
    const unconfirmed=harness([pending('g'),result]);await unconfirmed.settle();unconfirmed.hooks.showStep(2);await unconfirmed.hooks.runAction('policy');unconfirmed.message();await unconfirmed.settle();assert.equal(unconfirmed.hooks.step,2);assert.equal(unconfirmed.calls.filter(c=>c.body).length,2);
    if (result.error) { assert.equal(unconfirmed.get('ceremony-page').hidden,false);assert.equal(unconfirmed.get('review-host').hidden,true);assert.match(unconfirmed.get('status').textContent,/rejected/i); }
  }
  // One setup action walks through apps then spending approval automatically.
  // Only authenticated Machine confirmations can advance either stage.
  const guided=harness([pending('h'),{data:{state:'applied',petals:['polymarket']}},pending('i'),{data:[activeScope]}],{action:['policy','policy','activate','activate']});
  await guided.settle();guided.hooks.showStep(2);await guided.hooks.runAction('policy');
  const appReview=guided.hooks.pending.id;guided.message();await guided.settle();
  assert.equal(guided.hooks.step,3);assert.notEqual(guided.hooks.pending.id,appReview);
  guided.message();await guided.settle();assert.equal(guided.hooks.step,4);assert.equal(guided.hooks.pending,null);
  assert.deepEqual(guided.calls.filter(c=>c.body).map(c=>JSON.parse(c.body).action),['policy','policy','activate','activate']);
  // Delayed reconciliation must keep the outer setup and explanation visible.
  const delayed=harness([pending('j'),{data:{state:'applied',petals:['polymarket']}},pending('k'),{data:[activeScope]}],{action:['policy','policy','activate','activate'],pauseActions:[2,4]});
  await delayed.settle();delayed.hooks.showStep(2);await delayed.hooks.runAction('policy');delayed.message();await delayed.settle();
  for(const id of ['ceremony-page','review-host','setup-summary']) assert.equal(delayed.get(id).hidden,false,`${id} remains visible during app approval reconciliation`);
  assert.equal(delayed.get('setup-content').hidden,true,'choices must not flash back during reconciliation');
  assert.match(delayed.get('review-loading').textContent,/Checking/);
  assert.match(delayed.get('approval-purpose').textContent,/does not move funds/);
  delayed.release(2);await delayed.settle();assert.equal(delayed.hooks.step,3);
  assert.match(delayed.get('approval-title').textContent,/Automatic spending/);assert.equal(delayed.get('setup-content').hidden,true);
  delayed.message();await delayed.settle();assert.equal(delayed.get('review-host').hidden,false);assert.equal(delayed.get('setup-content').hidden,true);
  delayed.release(4);await delayed.settle();assert.equal(delayed.hooks.step,4);assert.equal(delayed.get('review-host').hidden,true);

  const noLink=harness([{data:{state:'awaiting_owner',ceremony_url:'http://localhost:28745/ceremony/token'}}]);await noLink.settle();noLink.hooks.showStep(2);
  await assert.rejects(noLink.hooks.runAction('policy'),/approval could not be opened/);
  assert.equal(noLink.get('next').disabled,true); // An unavailable approval cannot confirm setup.
  const busy=harness([{data:{state:'busy'}}]);await busy.settle();busy.hooks.showStep(2);await busy.hooks.runAction('policy');
  assert.match(busy.get('status').textContent,/Another approval/);assert.equal(busy.get('next').disabled,true);

  const chain=harness([pending('d'),pending('e')]);await chain.settle();chain.hooks.showStep(2);await chain.hooks.runAction('policy');const old=chain.hooks.pending.id;chain.message();await chain.settle();assert.equal(chain.hooks.step,2);assert.notEqual(chain.hooks.pending.id,old);
  const canceled=harness([pending('f')]);await canceled.settle();canceled.hooks.showStep(2);await canceled.hooks.runAction('policy');const canceledId=canceled.hooks.pending.id;canceled.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:canceledId,state:'canceled'}});await canceled.settle();assert.equal(canceled.hooks.pending,null);assert.equal(canceled.hooks.step,2);canceled.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:canceledId,state:'completed'}});await canceled.settle();assert.equal(canceled.calls.filter(c=>c.body).length,1);
  console.log('onboarding flow: Machine authority reconciliation gates completion; untrusted/stale/failed messages and chained reviews cannot advance');
})().catch(error=>{console.error(error);process.exitCode=1;});
