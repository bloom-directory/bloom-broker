const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../crates/bloom-broker/src/ceremony_assets/app.js'),'utf8');
const code = source.slice(source.indexOf('function validatedWalletSetupConnection('),source.indexOf('async function showCreatedWallet('));
const startup = source.slice(source.indexOf('const previewPath ='), source.indexOf('const authHeaders ='));
const helpers = source.slice(source.indexOf('function browserSessionStorage('), source.indexOf('function reportCeremonyError('));
const bridge = 'http://127.0.0.1:43251/onboarding/'+'a'.repeat(64)+'/';
function run(fragment, storage = new Map(), {reloadBeforeCompletion = false, token = "x".repeat(43), now = Date.now(), pathname = "/ceremony/" + token} = {}) {
  let tree, navigation;
  const location = new URL('http://localhost:28735' + pathname + fragment);
  const context = {URL,URLSearchParams,Date:{now:()=>now},Number,JSON,
    sessionStorage:{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    markDone(){},document:{getElementById:()=>({})},location,history:{replaceState:(_s,_t,url)=>{location.href=new URL(url,location).href;}},
    walletPageUrl:w=>'/wallet/'+encodeURIComponent(w),
    el:(tag,attrs,...children)=>({tag,attrs,children}),reviewNode:{replaceChildren:(...nodes)=>tree=nodes}};
  location.assign=url=>navigation=url;
  vm.createContext(context);vm.runInContext(helpers+startup+code,context);
  if (reloadBeforeCompletion) {
    assert.equal(location.hash, '', 'startup removes the fragment before completion');
    return run('', storage, {token, now:now+1000, pathname:location.pathname});
  }
  context.createdWalletView({wallet_id:'alice',accounts:[]});
  function find(nodes) { for(const n of nodes??[]) {if(n?.tag==='button' && n.children.includes('Continue setup')) return n;const found=find(n?.children);if(found)return found;} }
  return {button:find(tree),context,storage,get navigation(){return navigation;}};
}
const fresh=run('#setup='+encodeURIComponent(bridge));assert.ok(fresh.button);fresh.button.onclick();
assert.equal(fresh.navigation,'/onboarding/#bridge='+encodeURIComponent(bridge));
const resumed=run('',fresh.storage,{pathname:'/wallet/alice'});assert.ok(resumed.button,'same-tab wallet page can resume the connection');
assert.equal(run('').button,undefined,'public wallet ID alone cannot discover a capability');
for(const raw of ['https://attacker.example/',bridge+'?x=1',bridge+'#x','http://127.0.0.1:43251/other/','http://user@127.0.0.1:43251/onboarding/'+'a'.repeat(64)+'/']) {
 assert.equal(run('#setup='+encodeURIComponent(raw)).button,undefined,'reject invalid bridge');
}
const expired=new Map([['bloom.wallet.setup.alice',JSON.stringify({url:bridge,expires_at:Date.now()-1})]]);
assert.equal(run('',expired).button,undefined);
const other=run('',new Map([['bloom.wallet.setup.bob',JSON.stringify({url:bridge,expires_at:Date.now()+60000})]]));
assert.equal(other.button,undefined,'connections are wallet-specific');
const reloaded=run('#setup='+encodeURIComponent(bridge),new Map(),{reloadBeforeCompletion:true});
assert.ok(reloaded.button,'reload before wallet completion must retain Continue setup');
const launchTime = Date.now();
const pending = new Map();
run('#setup='+encodeURIComponent(bridge),pending,{now:launchTime});
const pendingKey = 'bloom.wallet.setup.ceremony.'+'x'.repeat(43);
const originalExpiry = JSON.parse(pending.get(pendingKey)).expires_at;
run('#setup='+encodeURIComponent(bridge),pending,{now:launchTime+60000});
assert.equal(JSON.parse(pending.get(pendingKey)).expires_at,originalExpiry,'reopening the same launch must not extend expiry');
assert.equal(run('',pending,{now:originalExpiry}).button,undefined,'pending and wallet connections expire at their original deadline');
const differentCeremony = new Map([[pendingKey,JSON.stringify({url:bridge,expires_at:launchTime+60000})]]);
assert.equal(run('',differentCeremony,{token:'y'.repeat(43),now:launchTime}).button,undefined,'pending connections cannot cross ceremony tokens');
console.log('wallet Continue setup: rendered button, reload before completion, ceremony isolation, unchanged expiry, recovery and invalid-origin rejection passed');
