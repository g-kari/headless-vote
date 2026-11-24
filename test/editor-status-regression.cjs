const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const src = fs.readFileSync(require('node:path').join(__dirname, '../src/routes/ui.ts'), 'utf8');
const guard = src.slice(src.indexOf('      const dialog = document.getElementById("status-dialog");'), src.indexOf('      })();\n    `)}\n    ${poll.status'));
const snap = src.slice(src.indexOf('function editorSnapshot()'), src.indexOf('async function submitPoll'));
function control(extra={}) {
  const events = {};
  return Object.assign({hidden:true, disabled:false, addEventListener(k,v){events[k]=v}, fire(k,e){return events[k]?.(e)}, focus(){this.focused=true}}, extra);
}
function setup(fetch) {
  const changes = {dirty:false, save:false, calls:0, reload:0};
  const action = control({getAttribute(){return 'published'}});
  const dialog = control({showModal(){this.open=true}, close(){this.open=false}});
  const flash=control(), confirm=control(), cancel=control();
  const form={dataset:{editorReady:'true'},dispatchEvent(){return !changes.dirty && !changes.save}};
  const els={"status-dialog":dialog,"status-confirm":confirm,"status-cancel":cancel,flash,"poll-form":form,"status-dialog-text":control(),"status-dialog-title":control()};
  vm.runInNewContext(guard, {Event, TENANT:'fixture', POLL:'fixture', document:{getElementById:id=>els[id],querySelectorAll:()=>[action]}, fetch:(...a)=>{changes.calls++;return fetch(...a)},location:{reload(){changes.reload++}}});
  return {action,dialog,flash,confirm,cancel,changes,form};
}
(async()=>{
  assert.ok(guard.length>1500 && snap.length>100);
  const fields=[{type:'text',value:'old'}, {type:'password',value:''}, {type:'file',files:[]}];
  const snapshot=()=>vm.runInNewContext(snap+'editorSnapshot()', {pollForm:{querySelectorAll:()=>fields}});
  const original=snapshot();
  fields[0].value='new'; assert.notEqual(snapshot(),original);
  fields[0].value='old'; assert.equal(snapshot(),original);
  fields[1].value='fake-passphrase'; assert.notEqual(snapshot(),original); assert.ok(!snapshot().includes(fields[1].value));
  fields[1].value=''; fields[2].files=[{}]; assert.notEqual(snapshot(),original);
  const noWrite=()=>{throw Error('unexpected write')};
  let t=setup(noWrite);
  t.changes.dirty=true; t.action.fire('click'); assert.equal(t.dialog.open,undefined); assert.match(t.flash.textContent,/保存していない/); assert.equal(t.changes.calls,0);
  t.changes.dirty=false; t.changes.save=true; t.action.fire('click'); assert.equal(t.changes.calls,0);
  t.changes.save=false; delete t.form.dataset.editorReady; t.action.fire('click'); assert.equal(t.dialog.open,undefined);
  t=setup(noWrite); t.action.fire('click'); t.changes.dirty=true; await t.confirm.fire('click'); assert.equal(t.changes.calls,0); assert.equal(t.dialog.open,false);
  let settle;
  t=setup(()=>new Promise(resolve=>{settle=resolve}));
  t.action.fire('click'); const req=t.confirm.fire('click'); await t.confirm.fire('click'); assert.equal(t.changes.calls,1); assert.equal(t.confirm.disabled,true);
  let cancelPrevented=false; t.dialog.fire('cancel',{preventDefault(){cancelPrevented=true}}); assert.equal(cancelPrevented,true);
  settle({ok:true}); await req; assert.equal(t.changes.reload,1);
  t=setup(async()=>({ok:false,status:409,json:async()=>({error:{message:'conflict'}})}));
  t.action.fire('click'); await t.confirm.fire('click'); assert.equal(t.flash.textContent,'conflict'); assert.equal(t.confirm.disabled,false); assert.equal(t.action.disabled,false); assert.equal(t.changes.reload,0);
  for(const fn of [async()=>{throw Error('offline')},async()=>({ok:false,status:503})]) {
    t=setup(fn); t.action.fire('click'); await t.confirm.fire('click'); t.action.fire('click'); await t.confirm.fire('click');
    assert.equal(t.changes.calls,1); assert.equal(t.changes.reload,0); assert.equal(t.action.disabled,true); assert.match(t.flash.textContent,/読み直し/);
  }
  console.log('Passed editor snapshot, unsaved gating, pending save, readiness, duplicate transition, rejection, and uncertain transition checks.');
})().catch(e=>{console.error(e);process.exitCode=1});
