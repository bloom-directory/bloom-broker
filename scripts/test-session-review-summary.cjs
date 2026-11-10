// Render the actual owner-reviewed terms without class or protocol dispatch.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../crates/bloom-broker/src/ceremony_assets/app.js'),'utf8');
const helpers=source.slice(source.indexOf('function escapeHtml('),source.indexOf('let expiryTimer ='));
const review=source.slice(source.indexOf('const PETAL_ACTIONS ='),source.indexOf('// Policy updates:'));
const ctx={canonicalJson:JSON.stringify,console};vm.createContext(ctx);vm.runInContext(helpers+review,ctx);
const asset={chain:'evm-1',asset:'0x'+'7'.repeat(40)};
const terms={subject:{package_hash:'a'.repeat(64)},selector:{kind:'petal',allowed_operation_classes:['example.payment']},limits:{max_operations:'1000'},expires_at_ms:'18446744073709551615',session_budget:{petal_policy:{persona:'trader',zero_spend_classes:['example.login','example.refresh'],zero_spend_rate_limit:{maximum:'60',duration_ms:'3600000'}},token_policy:{assets:[{asset,decimals:6,symbol:'TEST'}],member_templates:[]},per_action_value_limits:[{asset,maximum:'100000000'}],limits:{value_limits:[{asset,rolling_windows:[{maximum:'1000000000',duration_ms:'86400000'}]}]}}};
const plan={terms,package_display_name:'Reviewed payments',session_budget_id:'budget-identity'};
const describe=()=>ctx.describePetalApproval({canonical_plan:JSON.stringify(plan)});
const result=describe(),facts=new Map(result.primaryFacts);
assert.equal(result.heading,'Allow automatic actions for Reviewed payments');
assert.equal(facts.get('Integration'),'Reviewed payments');
assert.equal(facts.get('Permitted actions'),'example.payment');
assert.equal(facts.get('Per action'),'100 TEST on evm-1');
assert.equal(facts.get('Rolling allowance'),'Can sign 1000 TEST on evm-1 per 24 hours');
assert.match(facts.get('Accounting'),/additive/);assert.match(facts.get('Accounting'),/Cancelling signed orders does not refund/);assert.match(facts.get('Accounting'),/Open orders are not limited/);
assert.match(facts.get('Accounting'),/Token limits are shared by approvals using this budget/);
assert.match(facts.get('New allowance'),/new budget grants independent capacity; usage from different budgets does not carry over/);
assert.match(facts.get('New allowance'),/Approvals sharing this budget share its existing token usage/);
assert.match(facts.get('Zero-spend scope'),/These actions move no tokens from your wallet and have no spending limit/);
assert.match(facts.get('Zero-spend scope'),/margin can still be at risk/);
assert.match(facts.get('Zero-spend rate cap'),/shared by all listed classes in this member approval/);
assert.match(facts.get('Zero-spend rate cap'),/Other member approvals have separate caps, even when their token budget is shared/);
assert.match(facts.get('Zero-spend networks'),/Any network/);
assert.match(result.warning,/Amounts are reported by Reviewed payments, a reviewed Bloom package/);
assert.match(result.warning,/does not independently verify/);assert.doesNotMatch(result.warning,/compromised|understate|Protocol-verified/);
plan.standing_rearm=true;const rearm=describe();assert.equal(rearm.button,'Unlock with passkey');assert.match(rearm.sentence,/previous usage and authority identity stay unchanged/);assert.ok(!new Map(rearm.primaryFacts).has('New allowance'));
assert.deepEqual(rearm.primaryFacts,result.primaryFacts.filter(([label])=>label!=='New allowance'));
delete plan.package_display_name;terms.display_name='Untrusted caller label';assert.match(new Map(describe().primaryFacts).get('Integration'),/^Reviewed package /);
terms.selector={kind:'native_session',scope:{actions:['erc20_transfer'],chains:[{chain:'evm-1',chain_id:'1'}],destinations:[],any_erc20_recipient:true,tokens:[asset]}};
assert.match(JSON.stringify(describe()),/Any recipient \(ERC20 transfers only\)/);assert.equal(describe().heading,'Unlock existing transfer permission');
terms.selector.kind='system_session';assert.equal(describe(),null,'deleted draft selector must not render as active authority');
assert.ok(!source.includes('function describeIntegration('));
console.log('generic grant review: signed package name, real amounts, explicit zero scope/rate, additive capacity and unchanged rearm passed');
// Upstream policy cards must retain persona sentinels as permissions, not addresses.
vm.runInContext(source.slice(source.indexOf('// Policy updates:'), source.indexOf('function planDisclosures(')),ctx);
ctx.chainLabel=chain=>chain;
const policy=ctx.describePolicy({authority_diff:{
  added_destinations:[{chain:'evm-1',destination:'erc20:any-recipient'}],
  removed_destinations:[{chain:'evm-137',destination:'erc20:any-recipient'}],
  maximum_approval_lifetime_ms_before:'3600000',maximum_approval_lifetime_ms_after:'9007199254740991'
}});
assert.equal(policy.rules.length,3);
assert.match(policy.rules[0].label,/Allow ERC20 transfers to any recipient/);
assert.match(policy.rules[0].name,/separately approved token and gas allowance/);
assert.match(policy.rules[1].label,/Stop allowing ERC20 transfers/);
assert.match(policy.rules[2].name,/Until revoked/);
assert.ok(policy.rules.every(rule=>rule.value===undefined));
console.log('policy cards retain any-recipient scope and standing lifetime');
