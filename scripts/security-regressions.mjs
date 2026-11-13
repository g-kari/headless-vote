import { registerHooks } from 'node:module';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import assert from 'node:assert/strict';
registerHooks({resolve(specifier,context,next){
 if(specifier.startsWith('.') && context.parentURL){
  for(const suffix of ['.ts','/index.ts']){const candidate=new URL(specifier+suffix,context.parentURL);if(existsSync(fileURLToPath(candidate))) return next(candidate.href,context);}
 }
 return next(specifier,context);
}});
const root=fileURLToPath(new URL('../src/', import.meta.url));
const [schema,auth,local,keys,members,webhooks,objects,accounts,ballots,questions,domain,cleanup,identity]=await Promise.all(['schema','auth','platform/auth-local','keys','members','webhooks','platform/objects','account','ballots','questions','domain','object-cleanup','accounts'].map(x=>import(root+x+'.ts')));
class DB {
 constructor(migrated=false){this.db=new DatabaseSync(':memory:');this.db.exec('PRAGMA foreign_keys=ON');if(migrated){const dir=new URL('../migrations/',import.meta.url);for(const file of readdirSync(dir).filter(x=>x.endsWith('.sql')).sort())this.db.exec(readFileSync(new URL(file,dir),'utf8'));}else this.db.exec(schema.SCHEMA_SQL);}
 prepare(sql){let args=[]; const me=this;return {bind(...values){args=values;return this;}, execute(){const statement=me.db.prepare(sql);const bindings=Object.fromEntries(args.map((v,i)=>[String(i+1),v]));statement.setAllowUnknownNamedParameters(true);return {statement,bindings};},async first(){const {statement,bindings}=this.execute();return statement.get(bindings)??null;},async all(){const {statement,bindings}=this.execute();return {results:statement.all(bindings)};},async run(){return this.syncRun();},syncRun(){const {statement,bindings}=this.execute();const r=statement.run(bindings);return {success:true,meta:{changes:r.changes}};}};}
 async batch(stmts){this.db.exec('BEGIN');try{const results=stmts.map(x=>x.syncRun());this.db.exec('COMMIT');return results;}catch(e){this.db.exec('ROLLBACK');throw e;}}
}
const env={DB:new DB(),SESSION_SECRET:'dummy-unit-test-secret-not-production',AUTH_PROVIDER:'local',OBJECT_STORE:'memory'};
const check=async(name,fn)=>{await fn();console.log('PASS '+name)};
const messages=[];const sender={id:'test',async send(x){messages.push(x.text)}};const token=()=>decodeURIComponent(/token=([^\s]+)/.exec(messages.at(-1))[1]);
const session=async cookie=>auth.getSessionUser({env,req:{url:'https://vote.test/',header:k=>k==='cookie'?cookie.split(';')[0]:undefined}});
await check('atomic local recovery revokes sessions and all reset links',async()=>{
 await local.registerLocalUser(env,{email:'u@example.com',password:'old-password-123',name:'User',origin:'https://vote.test'},sender);await local.verifyLocalEmail(env,token());
 const identity=await local.loginLocalUser(env,'u@example.com','old-password-123');
 const cookie=await auth.newSessionCookieForToken(env,{},identity.sub,'https://vote.test',identity.sessionVersion);assert.ok(await session(cookie));
 await local.requestPasswordReset(env,'u@example.com','https://vote.test',sender);const older=token();await local.requestPasswordReset(env,'u@example.com','https://vote.test',sender);const newer=token();
 const results=await Promise.allSettled(['one','two'].map(x=>local.resetLocalPassword(env,newer,'new-password-'+x)));assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(await session(cookie),null);await assert.rejects(local.resetLocalPassword(env,older,'attacker-password'));
 const delayed=await auth.newSessionCookieForToken(env,{},identity.sub,'https://vote.test',identity.sessionVersion);assert.equal(await session(delayed),null);
});
const provision=async()=>keys.provisionTenant(env,'Test',null);
await check('one key rotation successor, revoked snapshot denied',async()=>{
 const {tenantId,apiKey}=await provision();const snapshot=await keys.findActiveApiKey(env,apiKey);
 const r=await Promise.allSettled([1,2].map(()=>keys.rotatePresentedKey(env,tenantId,snapshot)));assert.equal(r.filter(x=>x.status==='fulfilled').length,1);assert.equal(await keys.findActiveApiKey(env,apiKey),null);
 const row=await env.DB.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE tenant_id=?1 AND revoked_at IS NULL').bind(tenantId).first();assert.equal(row.n,1);
});
await check('atomic key quota and last-owner preservation',async()=>{
 const {tenantId}=await provision();const oneId=(await identity.resolveAccount(env,'one')).id;const twoId=(await identity.resolveAccount(env,'two')).id;const actor={kind:'session',tenantId,accountId:oneId,role:'owner'};
 await env.DB.prepare('UPDATE tenants SET quota_keys=2 WHERE id=?1').bind(tenantId).run();const r=await Promise.allSettled([1,2].map(x=>keys.issueApiKey(env,tenantId,'key'+x,'read',actor)));assert.equal(r.filter(x=>x.status==='fulfilled').length,1);
 await members.addMember(env,tenantId,oneId,'owner',actor);await members.addMember(env,tenantId,twoId,'owner',actor);const removed=await Promise.allSettled([oneId,twoId].map(x=>members.removeMember(env,tenantId,x,actor)));assert.equal(removed.filter(x=>x.status==='fulfilled').length,1);
 const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM tenant_members WHERE tenant_id=?1 AND role='owner'").bind(tenantId).first();assert.equal(row.n,1);
});
await check('webhook special-address rejection and atomic quota',async()=>{
 for(const url of ['http://localhost/h','https://[::1]/h','https://[fd00::1]/h','https://[::ffff:127.0.0.1]/h','https://127.1/h','https://169.254.169.254/h']) assert.throws(()=>webhooks.assertWebhookUrl(url),url);
 assert.equal(webhooks.assertWebhookUrl('https://hooks.example.com/h'),'https://hooks.example.com/h');
 const {tenantId}=await provision();await env.DB.prepare('UPDATE tenants SET quota_webhooks=1 WHERE id=?1').bind(tenantId).run();const r=await Promise.allSettled([1,2].map(()=>webhooks.createWebhook(env,tenantId,'https://hooks.example.com/h',['vote.cast'])));assert.equal(r.filter(x=>x.status==='fulfilled').length,1);
});
await check('deletion queues and cleans images, retains other tenants',async()=>{
 const a=await provision(),b=await provision();const store=objects.createObjectStore(env);for(let i=0;i<205;i++)await store.put(`t/${a.tenantId}/${i}`,new Uint8Array([1]),'image/png');await store.put(`t/${b.tenantId}/keep`,new Uint8Array([1]),'image/png');await accounts.deleteWorkspace(env,a.tenantId);assert.equal(await store.head(`t/${a.tenantId}/0`),false);assert.equal(await store.head(`t/${a.tenantId}/204`),false);assert.ok(await store.head(`t/${b.tenantId}/keep`));assert.equal(await env.DB.prepare('SELECT * FROM object_cleanup WHERE tenant_id=?1').bind(a.tenantId).first(),null);
});
await check('concurrent account deletion cannot strand ownerless live workspace',async()=>{
 const {tenantId}=await provision();const owner1Id=(await identity.resolveAccount(env,'owner1')).id;const owner2Id=(await identity.resolveAccount(env,'owner2')).id;const actor={kind:'session',tenantId,accountId:owner1Id,role:'owner'};await members.addMember(env,tenantId,owner1Id,'owner',actor);await members.addMember(env,tenantId,owner2Id,'owner',actor);await Promise.all([owner1Id,owner2Id].map(x=>accounts.deleteAccountData(env,x)));const row=await env.DB.prepare('SELECT * FROM tenants WHERE id=?1').bind(tenantId).first();assert.equal(row,null);
});
async function pollFixture(){const {tenantId}=await provision();const id=crypto.randomUUID(),now=new Date().toISOString();await env.DB.prepare("INSERT INTO polls (id,tenant_id,question,status,created_at,updated_at,revision) VALUES (?1,?2,'Q','published',?3,?3,'initial')").bind(id,tenantId,now).run();await env.DB.prepare('UPDATE tenants SET quota_votes_per_day=1 WHERE id=?1').bind(tenantId).run();return domain.getPollRow(env,id);}
await check('stale vote status/revision/schedule/login cannot write ballot',async()=>{
 for(const update of ["status='closed'","status='draft'","revision='new'","require_login=1","closes_at='2000-01-01T00:00:00.000Z'","opens_at='2999-01-01T00:00:00.000Z'"]){const p=await pollFixture();await env.DB.prepare(`UPDATE polls SET ${update} WHERE id=?1`).bind(p.id).run();await assert.rejects(ballots.upsertBallot(env,p,'anon:x','{}',false));assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM vote_ballots WHERE poll_id=?1').bind(p.id).first()).n,0);}
});
await check('one daily vote quota slot and atomic question CAS',async()=>{
 const p=await pollFixture();const r=await Promise.allSettled([1,2].map(x=>ballots.upsertBallot(env,p,'anon:'+x,'{}',false)));assert.equal(r.filter(x=>x.status==='fulfilled').length,1);assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM vote_events WHERE poll_id=?1').bind(p.id).first()).n,1);
 const p2=await pollFixture();const input=[{prompt:'Text',description:'',image_key:null,kind:'text',required:false,options:[]}];await env.DB.batch(questions.replaceQuestionStatements(env,p2.id,input,p2.revision));const before=await questions.listQuestionRows(env,p2.id);await env.DB.batch([env.DB.prepare("UPDATE polls SET revision='loser' WHERE id=?1 AND revision='stale'").bind(p2.id),...questions.replaceQuestionStatements(env,p2.id,input,'loser')]);assert.deepEqual(await questions.listQuestionRows(env,p2.id),before);
});
await check('migration-chain question replacement removes old options without FK cascade',async()=>{
 const migrated={...env,DB:new DB(true)};const {tenantId}=await keys.provisionTenant(migrated,'Migrated',null);const id=crypto.randomUUID(),now=new Date().toISOString();
 await migrated.DB.prepare("INSERT INTO polls (id,tenant_id,question,status,created_at,updated_at,revision) VALUES (?1,?2,'Q','draft',?3,?3,'initial')").bind(id,tenantId,now).run();
 const input=[{prompt:'Q',description:'',image_key:null,kind:'single',required:true,options:[{label:'A',image_key:null},{label:'B',image_key:null}]}];
 await migrated.DB.batch(questions.replaceQuestionStatements(migrated,id,input,'initial'));
 await migrated.DB.batch(questions.replaceQuestionStatements(migrated,id,input,'initial'));
 assert.equal((await migrated.DB.prepare('SELECT COUNT(*) AS n FROM options WHERE poll_id=?1').bind(id).first()).n,2);
});
await check('migration 0017 converts sub-keyed data to internal account ids',async()=>{
 const dir=new URL('../migrations/',import.meta.url);const files=readdirSync(dir).filter(x=>x.endsWith('.sql')).sort();
 const raw=new DatabaseSync(':memory:');raw.exec('PRAGMA foreign_keys=ON');
 for(const file of files.filter(x=>x<'0017'))raw.exec(readFileSync(new URL(file,dir),'utf8'));
 const now=new Date().toISOString();
 raw.prepare("INSERT INTO tenants (id,name,api_key_hash,created_at) VALUES ('t1','Legacy','h',?1)").run({1:now});
 raw.prepare("INSERT INTO tenant_members (tenant_id,user_sub,role,created_at) VALUES ('t1','legacy-user','owner',?1)").run({1:now});
 raw.prepare("INSERT INTO session_epochs (sub,epoch) VALUES ('legacy-user',3)").run();
 raw.prepare("INSERT INTO audit_events (id,tenant_id,actor,action,target,detail,created_at) VALUES ('a1','t1','session:legacy-user','member.add','legacy-user','owner',?1)").run({1:now});
 raw.prepare("INSERT INTO local_users (id,email,password_hash,name,email_verified_at,created_at) VALUES ('lu1','Local@Example.com','x','Local',?1,?1)").run({1:now});
 raw.exec(readFileSync(new URL('0017_internal_accounts.sql',dir),'utf8'));
 const account=raw.prepare("SELECT * FROM accounts WHERE subject='legacy-user'").get();assert.ok(account?.id);
 assert.match(account.id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
 const memberCols=raw.prepare("PRAGMA table_info(tenant_members)").all().map(r=>r.name);assert.ok(memberCols.includes('account_id'));assert.ok(!memberCols.includes('user_sub'));
 assert.equal(raw.prepare("SELECT account_id FROM tenant_members WHERE tenant_id='t1'").get().account_id,account.id);
 const epochCols=raw.prepare("PRAGMA table_info(session_epochs)").all().map(r=>r.name);assert.ok(!epochCols.includes('sub'));
 const epochRow=raw.prepare("SELECT account_id,epoch FROM session_epochs").get();assert.equal(epochRow.account_id,account.id);assert.equal(epochRow.epoch,3);
 const audit=raw.prepare("SELECT actor,target FROM audit_events WHERE id='a1'").get();assert.equal(audit.actor,'session:'+account.id);assert.equal(audit.target,account.id);
 const local=raw.prepare("SELECT * FROM accounts WHERE subject='local:lu1'").get();assert.equal(local.email,'local@example.com');assert.equal(local.name,'Local');
 raw.close();
});
await check('late upload generation survives cleanup acknowledgement and retries',async()=>{
 const id=crypto.randomUUID();const prefix=`t/${id}/`;const files=new Set([prefix+'old']);
 await env.DB.prepare("INSERT INTO object_cleanup (tenant_id,created_at,generation) VALUES (?1,?2,'old')").bind(id,new Date().toISOString()).run();let late=true;
 const fake={...env,OBJECT_STORE:'r2',IMAGES:{async list(){const page=[...files].map(key=>({key}));if(late){late=false;files.add(prefix+'late');await env.DB.prepare("UPDATE object_cleanup SET generation='new' WHERE tenant_id=?1").bind(id).run();}return {objects:page,truncated:false};},async delete(names){for(const name of names)files.delete(name);}}};
 await cleanup.drainObjectCleanup(fake,1);assert.ok(files.has(prefix+'late'));assert.ok(await env.DB.prepare('SELECT 1 AS ok FROM object_cleanup WHERE tenant_id=?1').bind(id).first());
 await cleanup.drainObjectCleanup(fake,1);assert.equal(files.size,0);assert.equal(await env.DB.prepare('SELECT 1 AS ok FROM object_cleanup WHERE tenant_id=?1').bind(id).first(),null);
});
console.log('All 11 dependency-free security regression groups passed (SQLite shim, not Workers/Vitest).');
