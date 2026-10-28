// Exercise the shipped interpretation of signed session terms, not UI-supplied caps.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../crates/bloom-broker/src/ceremony_assets/app.js'),'utf8');
const helpers=source.slice(source.indexOf('function escapeHtml('),source.indexOf('let expiryTimer ='));
const review=source.slice(source.indexOf('const PETAL_ACTIONS ='),source.indexOf('// Policy updates:'));
const ctx={canonicalJson:JSON.stringify,console};vm.createContext(ctx);vm.runInContext(helpers+review,ctx);
const asset={chain:'evm-137',asset:'0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb'};
const terms={subject:{package_hash:'a'.repeat(64)},selector:{kind:'petal',allowed_operation_classes:['polymarket.order.poly1271']},limits:{max_operations:'18446744073709551615'},expires_at_ms:'18446744073709551615',session_budget:{token_policy:{assets:[{asset,decimals:6,symbol:'pUSD'}],member_templates:[]},per_action_value_limits:[{asset,maximum:'100000000'}],limits:{value_limits:[{asset,rolling_windows:[{maximum:'1000000000',duration_ms:'86400000'}]}]}}};
const result=ctx.describePetalApproval({canonical_plan:JSON.stringify({terms})});
assert.equal(result.heading,'Allow automatic Polymarket buys');
assert.ok(!result.sentence.includes('this Petal'));
const facts=new Map(result.primaryFacts);
assert.equal(facts.get('Integration'),'Polymarket integration');
assert.match(facts.get('Permitted actions'),/BUY/);
assert.equal(facts.get('Per action'),'100 pUSD on evm-137');
assert.equal(facts.get('Rolling allowance'),'1000 pUSD on evm-137 per 24 hours');
assert.equal(facts.get('Permission lasts'),'Until you revoke this permission');
assert.ok(!JSON.stringify(result).includes('CoinGecko')); 
assert.match(result.warning,/app-reported/);
terms.selector.allowed_operation_classes=['unknown.protocol'];
const fallback=ctx.describePetalApproval({canonical_plan:JSON.stringify({terms})});
assert.match(fallback.primaryFacts[0][1],/^Installed app aaaaaaaa/,'unknown app must be identified by package, not given a made-up name');
assert.ok(!fallback.sentence.includes('this Petal'));
console.log('signed session review: named integration, BUY scope, actual token caps, standing authority and honest unknown-package fallback passed');
terms.selector.allowed_operation_classes=['polymarket.order.poly1271'];
const rearm=ctx.describePetalApproval({canonical_plan:JSON.stringify({terms,standing_rearm:true})});
assert.match(rearm.heading,/Unlock/);assert.equal(rearm.button,'Unlock with passkey');
assert.match(rearm.sentence,/previous usage and authority identity stay unchanged/);
assert.deepEqual(rearm.primaryFacts,result.primaryFacts,'rearm cannot show different allowances');

terms.selector={kind:'system_session',scope:{actions:['erc20_transfer'],chains:[{chain:'evm-1',chain_id:'1'}],destinations:[],any_erc20_recipient:true}};
const transfers=ctx.describePetalApproval({canonical_plan:JSON.stringify({terms})});
assert.match(JSON.stringify(transfers),/Any recipient \(ERC20 transfers only\)/);

assert.equal(transfers.heading,'Allow automatic ERC20 transfers');
assert.equal(new Map(transfers.primaryFacts).get('Recipients'),'Any recipient (ERC20 transfers only)');
assert.ok(transfers.primaryFacts.some(([label])=>label==='Rolling allowance'));
