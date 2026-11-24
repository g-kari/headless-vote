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
function setupSave({pollId = '', fetch, upload = async () => {}}) {
  const button = {disabled:false};
  const form = {dataset:{}, inert:false, querySelector:()=>button};
  const state = {calls:0, errors:[], records:[], messages:[], methods:[]};
  const elements = {'poll-form':form, question:{value:'Synthetic draft'}, description:{value:'Keep me'}};
  const nodes = {getElementById:(id)=>elements[id] || {value:'', checked:false}, querySelector:()=>({value:'token'})};
  const scope = {document:nodes, TENANT:'fixture', POLL_ID:pollId, validateForm:()=>[], uploadFrom:upload,
    showServerError:message=>state.messages.push(message), errorEl:{style:{}}, window:{scrollTo(){}}, location:{href:''},
    fetch:async (url, request)=>{state.calls++;state.methods.push(request.method);return fetch(state);}};
  const start=src.indexOf("const pollForm = document.getElementById('poll-form');");
  const end=src.indexOf("pollForm.addEventListener('submit', submitPoll);",start);
  assert.ok(start>=0 && end>start);
  const submit=vm.runInNewContext(src.slice(start,end)+'submitPoll',scope);
  return {state, form, button, location:scope.location, question:elements.question,
    submit:()=>submit({preventDefault(){}})};
}
async function checkSaveSubmissions() {
  // The synthetic server records the draft before the connection drops.
  for (const outcome of ['disconnect','timeout','server error','missing ID']) {
    const t=setupSave({fetch:async s=>{
      s.records.push('created');
      if(outcome==='disconnect') throw Error('response lost');
      if(outcome==='timeout') return {ok:false,status:408};
      if(outcome==='server error') return {ok:false,status:503};
      return {ok:true,status:201,json:async()=>({})};
    }});
    await t.submit();
    assert.equal(t.form.inert,false);
    assert.equal(t.question.value,'Synthetic draft');
    assert.equal(t.button.disabled,true);
    assert.match(t.state.messages[0],/再送は止めました/);
    await t.submit();
    assert.equal(t.state.calls,1);
    assert.equal(t.state.records.length,1);
  }
  let uploads=0;
  const beforeSend=setupSave({upload:async()=>{if(++uploads===1)throw Error('upload failed');},
    fetch:async()=>({ok:true,status:201,json:async()=>({poll:{id:'new'}})})});
  await beforeSend.submit();
  assert.equal(beforeSend.state.calls,0);
  assert.equal(beforeSend.button.disabled,false);
  await beforeSend.submit();
  assert.deepEqual(beforeSend.state.methods,['POST']);
  assert.match(beforeSend.location.href,/polls\/new$/);

  const rejected=setupSave({fetch:async s=>s.calls===1?{ok:false,status:400,json:async()=>({error:{message:'invalid'}})}
    :{ok:true,status:201,json:async()=>({poll:{id:'new'}})}});
  await rejected.submit();
  assert.equal(rejected.button.disabled,false);
  assert.equal(rejected.state.messages[0],'invalid');
  await rejected.submit();
  assert.equal(rejected.state.calls,2);

  const existing=setupSave({pollId:'existing',fetch:async()=>{throw Error('response lost');}});
  await existing.submit();
  assert.deepEqual(existing.state.methods,['PATCH']);
  assert.equal(existing.button.disabled,false);
  assert.match(existing.state.messages[0],/確認できません/);
}
(async()=>{
  await checkSaveSubmissions();
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
  console.log('Passed editor snapshot, unsaved gating, pending save, readiness, duplicate transition, rejection, uncertain transition, and save-retry checks.');
})().catch(e=>{console.error(e);process.exitCode=1});
