const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../crates/bloom-broker/src/ceremony_assets/app.js'),'utf8');
const code = source.slice(source.indexOf('function walletSetupContinuation('),source.indexOf('async function showCreatedWallet('));
const bridge = 'http://127.0.0.1:43251/onboarding/'+'a'.repeat(64)+'/';
function run(fragment, storage = new Map()) {
  let tree, navigation;
  const context = {URL,URLSearchParams,Date,Number,JSON,walletSetupFragment:fragment,
    sessionStorage:{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v)},
    markDone(){},document:{getElementById:()=>({})},location:{assign:url=>navigation=url},
    walletPageUrl:w=>'/wallet/'+encodeURIComponent(w),
    el:(tag,attrs,...children)=>({tag,attrs,children}),reviewNode:{replaceChildren:(...nodes)=>tree=nodes}};
  vm.createContext(context);vm.runInContext(code,context);
  context.createdWalletView({wallet_id:'alice',accounts:[]});
  function find(nodes) { for(const n of nodes??[]) {if(n?.tag==='button' && n.children.includes('Continue setup')) return n;const found=find(n?.children);if(found)return found;} }
  return {button:find(tree),context,storage,get navigation(){return navigation;}};
}
const fresh=run('#setup='+encodeURIComponent(bridge));assert.ok(fresh.button);fresh.button.onclick();
assert.equal(fresh.navigation,'/onboarding/#bridge='+encodeURIComponent(bridge));
const resumed=run('',fresh.storage);assert.ok(resumed.button,'same-tab wallet page can resume the connection');
assert.equal(run('').button,undefined,'public wallet ID alone cannot discover a capability');
for(const raw of ['https://attacker.example/',bridge+'?x=1',bridge+'#x','http://127.0.0.1:43251/other/','http://user@127.0.0.1:43251/onboarding/'+'a'.repeat(64)+'/']) {
 assert.equal(run('#setup='+encodeURIComponent(raw)).button,undefined,'reject invalid bridge');
}
const expired=new Map([['bloom.wallet.setup.alice',JSON.stringify({url:bridge,expires_at:Date.now()-1})]]);
assert.equal(run('',expired).button,undefined);
const other=run('',new Map([['bloom.wallet.setup.bob',JSON.stringify({url:bridge,expires_at:Date.now()+60000})]]));
assert.equal(other.button,undefined,'connections are wallet-specific');
console.log('wallet Continue setup: rendered button, same-tab navigation, recovery, expiry and invalid-origin rejection passed');
