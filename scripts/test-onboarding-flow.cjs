// Execute the shipped wizard in Node's VM with only the DOM surface it uses.
// No authority or passkey operation is simulated: assertions cover UI gating
// and the order of calls to the existing Machine reconciliation API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../crates/bloom-broker/src/ceremony_assets/onboarding/app.js'), 'utf8');
const baseState = {selected_wallet:'alice',wallet_choices:[{id:'alice'}],machine:{available:true},config:{exists:true,setup_complete:true,persona:{preset:'trader'},persona_limits:{per_action_usd:'100',daily_usd:'1000',session_duration_secs:'86400'},petals:['polymarket']},catalog:[]};
function harness(actions) {
  const elements = new Map(), listeners = {}, calls = [];
  function element() { return {hidden:false,value:'',options:[],style:{},dataset:{},classList:{toggle(){}},contentWindow:{},querySelectorAll:()=>[],addEventListener(){},append(){},replaceChildren(){},removeAttribute(name){delete this[name];},add(option){this.options.push(option);}}; }
  const get = id => {if (!elements.has(id)) elements.set(id,element()); return elements.get(id);};
  get('setup-form').elements = {persona:{value:'trader'}};
  const location = new URL('http://localhost:18734/onboarding/');
  location.hash = '#bridge=' + encodeURIComponent('http://127.0.0.1:54321/onboarding/'+'a'.repeat(64)+'/');
  const response = (data,ok=true) => ({ok,status:ok?200:409,json:async()=>data,text:async()=>JSON.stringify(data)});
  let sessionCount = 0;
  const sandbox = {URL,URLSearchParams,Date,Number,JSON,Option:function(text,value){this.value=value;},location,history:{replaceState(){}},document:{getElementById:get,querySelectorAll:()=>[],createElement:element},window:{addEventListener:(name,fn)=>{listeners[name]=fn;}},setTimeout:()=>1,clearTimeout(){},ResizeObserver:function(){},fetch:async(raw,options={})=>{
    const url = new URL(raw,location); calls.push({url:url.href,body:options.body});
    if (url.pathname.endsWith('/api/state')) return response(JSON.parse(JSON.stringify(baseState)));
    if (url.pathname.endsWith('/api/action')) {assert.equal(JSON.parse(options.body).action,'policy'); assert.ok(actions.length,'unexpected reconciliation'); return response(actions.shift());}
    if (url.pathname === '/api/session') return response({ceremony_id:String(++sessionCount).repeat(64),expires_at_ms:Date.now()+60000});
    throw new Error('unexpected fetch '+url);
  }};
  vm.createContext(sandbox);
  vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.hooks={runAction,showStep,refresh,get step(){return step},get pending(){return activeReview}};})();'),sandbox);
  const settle = async()=>{for(let i=0;i<8;i++) await new Promise(resolve=>setImmediate(resolve));};
  const message = overrides => listeners.message({origin:location.origin,source:get('ceremony-frame').contentWindow,data:{type:'bloom.onboarding.ceremony',ceremony_id:sandbox.hooks.pending?.id,state:'completed'},...overrides});
  return {hooks:sandbox.hooks,calls,message,settle,get};
}
const pending = token => ({ceremony_url:'http://localhost:18734/ceremony/'+token.repeat(43),data:{status:'awaiting_owner'}});
(async()=>{
  const h = harness([pending('b'),{data:{status:'applied'}}]); await h.settle(); h.hooks.showStep(2); await h.hooks.runAction('policy');
  const before=h.calls.length;
  h.message({origin:'https://attacker.example'}); h.message({source:{}}); h.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:'f'.repeat(64),state:'completed'}}); await h.settle();
  assert.equal(h.calls.length,before); assert.equal(h.hooks.step,2);
  h.message(); await h.settle(); assert.equal(h.hooks.step,3);
  assert.equal(h.calls.filter(c=>c.body).length,2);
  for (const result of [{data:{status:'awaiting_owner'}},{data:{status:'busy'}},{error:'Reconciliation rejected'}]) {
    const unconfirmed=harness([pending('g'),result]);await unconfirmed.settle();unconfirmed.hooks.showStep(2);await unconfirmed.hooks.runAction('policy');unconfirmed.message();await unconfirmed.settle();assert.equal(unconfirmed.hooks.step,2);assert.equal(unconfirmed.calls.filter(c=>c.body).length,2);
    if (result.error) { assert.equal(unconfirmed.get('ceremony-page').hidden,false);assert.equal(unconfirmed.get('review-host').hidden,true);assert.match(unconfirmed.get('status').textContent,/rejected/i); }
  }
  const chain=harness([pending('d'),pending('e')]);await chain.settle();chain.hooks.showStep(2);await chain.hooks.runAction('policy');const old=chain.hooks.pending.id;chain.message();await chain.settle();assert.equal(chain.hooks.step,2);assert.notEqual(chain.hooks.pending.id,old);
  const canceled=harness([pending('f')]);await canceled.settle();canceled.hooks.showStep(2);await canceled.hooks.runAction('policy');const canceledId=canceled.hooks.pending.id;canceled.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:canceledId,state:'canceled'}});await canceled.settle();assert.equal(canceled.hooks.pending,null);assert.equal(canceled.hooks.step,2);canceled.message({data:{type:'bloom.onboarding.ceremony',ceremony_id:canceledId,state:'completed'}});await canceled.settle();assert.equal(canceled.calls.filter(c=>c.body).length,1);
  console.log('onboarding flow: Machine authority reconciliation gates completion; untrusted/stale/failed messages and chained reviews cannot advance');
})().catch(error=>{console.error(error);process.exitCode=1;});
