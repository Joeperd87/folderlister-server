// Runs the actual embedded editor functions with a fake network, never eBay.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../server/web_editor.py'), 'utf8');
const script = source.split('<script>')[1].split('</script>')[0];
new vm.Script(script); // Syntax-check the complete embedded JavaScript.
const publish = script.slice(script.indexOf('  function publish(rows){'), script.indexOf('  // ------------------- html editor'));
// The real time helpers, so scheduling is exercised instead of stubbed.
const timeHelpers = script.slice(script.indexOf('  function pad2(n)'), script.indexOf('  // ------------------- site/policies/aspects/conditions'));
const issues = script.slice(script.indexOf('  function reviewIssues(row){'), script.indexOf("  document.getElementById('guideCheck')"));
function context(post, confirmation = true) {
  const c = {
    console:{...console, error:()=>{}}, Intl, Date, Set, Promise, publicationBusy: false, _noPolicies: false,
    SITE:'US', POL:{defaults:{}}, CURRENCY:'USD', GLOBAL_START_DT:null, INTERVAL_MIN:0,
    confirm:()=>confirmation, alert:(m)=>{c.alerts.push(String(m));}, status:()=>{}, alerts:[],
    showPublishOverlay:()=>{}, hidePublishOverlay:()=>{}, setPublishOverlayProgress:()=>{},
    renderBody:()=>{}, updatePublishedToggle:()=>{}, showPublicationResults:(...args)=>{c.result = args;},
    postJSON:post, ismulti:r=>Array.isArray(r.variations) && r.variations.length > 0,
    document:{querySelectorAll:()=>[], querySelector:()=>null}, window:{open:()=>{}},
  };
  vm.createContext(c); vm.runInContext(timeHelpers + issues + publish, c); return c;
}
const row = n => ({title:`Coin ${n}`, category_id:'1', quantity:1, price:3, picture_urls:['photo']});
const settle = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  let calls = 0;
  const c = context(async (_url, body) => { calls++; return {ok:true, results:body.rows.map(()=>({ok:true, item_id:'123'}))}; });
  const rows = [row(1), row(2)];
  c.publish(rows); c.publish(rows); await settle();
  assert.equal(calls, 1, 'double click cannot start two publications');
  assert(rows.every(r => r._published));
  c.publish(rows); await settle(); assert.equal(calls, 1, 'successful items are excluded');
  assert.equal(c.publicationBusy, false);

  calls = 0;
  const failed = context(async (_url, body) => {
    calls++; if (calls === 2) throw Error('offline');
    return {ok:true, results:body.rows.map(()=>({ok:true, item_id:'123'}))};
  });
  const big = Array.from({length:21}, (_,n)=>row(n));
  failed.publish(big); await settle();
  assert(big.slice(0,20).every(r=>r._published), 'early chunks survive a later failure');
  assert.equal(big[20]._publicationUnknown, true);
  assert.equal(failed.publicationBusy, false);
  failed.publish(big); await settle(); assert.equal(calls, 2, 'unknown result cannot be blindly retried');

  calls = 0;
  const cancel = context(async ()=>{calls++;}, false);
  cancel.publish([row(1)]); await settle(); assert.equal(calls, 0);
  cancel.publish([]); assert.equal(calls, 0);

  const missing = row(1); missing.price = 0; missing.quantity = 1.5;
  assert(c.reviewIssues(missing).some(([field])=>field==='price'));
  assert(c.reviewIssues(missing).some(([field])=>field==='quantity'));
  assert(c.reviewIssues(missing).some(([field])=>field==='shipping_profile'));
  missing.variations = [{price:3, quantity:1}];
  assert(!c.reviewIssues(missing).some(([field])=>field==='price'), 'variation parent has no independent price');
  // --- scheduling ---
  const future = () => new Date(Date.now() + 48*3600*1000);
  const localMinute = d => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}T${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;

  // A row corrected to a future time must not be reported as moved to now,
  // even when an earlier attempt did move it.
  const sched = context(async (_url, body) => ({ok:true, results:body.rows.map(()=>({ok:true, item_id:'1'}))}));
  const late = Object.assign(row(1), {schedule_time:'2020-01-02T03:04'});
  sched.ensureUtcSchedule(late);
  assert.equal(late._schedule_bumped, true, 'a past time is moved to now');
  late.schedule_time = localMinute(future());
  sched.ensureUtcSchedule(late);
  assert.equal(late._schedule_bumped, false, 'the flag describes this attempt, not the previous one');
  assert(late.schedule_time_utc.startsWith(String(future().getUTCFullYear())), 'the corrected time survives');

  // Cancelling at the confirmation must leave the schedules untouched.
  const kept = context(async ()=>({ok:true, results:[]}), false);
  const untouched = Object.assign(row(1), {schedule_time:'2020-01-02T03:04'});
  kept.publish([untouched]); await settle();
  assert.equal(untouched.schedule_time, '2020-01-02T03:04', 'a cancelled publish rewrites nothing');
  assert(kept.alerts.some(m => m.includes('Continue and they are moved')), 'the warning comes before the confirmation');

  console.log('PASS: editor syntax, opt-in review checks, publication confirmation, double-click guard, partial failure, unknown outcomes and schedule handling');
})().catch(e=>{console.error(e); process.exitCode=1;});
