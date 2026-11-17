import {jobs,reports,archiveKeys} from '../api/entities.js';
import {download} from '../api/client.js';
import {workspace} from '../stores/workspace.js';
import {session} from '../stores/session.js';
import {heading} from '../components/common/shell.js';
import {esc,date,notify} from '../utils/dom.js';
import {submit} from '../hooks/forms.js';

const STATES=[['pending','待迁移'],['migrating','迁移中'],['failed','失败'],['done','完成']];
const KEY_STATUS={active:'生效中',rotating:'轮换中（待退役）',retired:'已退役'};
const ROTATION_STATUS={running:'迁移中',completed:'已完成',attention:'存在失败',superseded:'已被新轮换替代'};
const admin=()=>session.user.role==='admin';

function keyPanel(data){
 const rows=data.keys.map(k=>'<tr><td>v'+k.version+'</td><td>'+esc(KEY_STATUS[k.status]||k.status)+'</td><td>'+k.files+' 份</td><td>'+k.in_use_leases+'</td><td><code>'+esc(k.fingerprint.slice(0,16))+'…</code></td><td>'+date(k.created_at)+'</td><td>'+(k.can_retire?'<button class="text-button" data-retire="'+k.version+'">退役旧密钥</button>':'—')+'</td></tr>').join('')||'<tr><td colspan="7">尚未生成归档密钥。</td></tr>';
 const states=STATES.map(([name,label])=>'<div><span>'+esc(label)+'</span><strong>'+((data.states[name]||{}).count||0)+'</strong></div>').join('');
 return '<section class="panel"><div class="section-title"><h2>归档加密密钥</h2><span>当前生效 v'+esc(data.active_version||'—')+' · 密钥与归档文件分开保存</span></div>'+
  '<div class="key-actions"><button class="button primary" id="rotate-keys" '+(admin()?'':'disabled')+'>发起密钥轮换</button><button class="button" id="migrate-now" '+(admin()?'':'disabled')+'>继续迁移</button><button class="button" id="retry-failed" '+(admin()?'':'disabled')+'>重试失败项</button></div>'+
  '<div class="numbers archive-states">'+states+(data.legacy_plaintext?'<div><span>未加密存量</span><strong>'+data.legacy_plaintext+'</strong></div>':'')+'</div>'+
  '<div class="table-wrap"><table><thead><tr><th>版本</th><th>状态</th><th>归档归属</th><th>在途读取</th><th>指纹</th><th>创建时间</th><th>操作</th></tr></thead><tbody>'+rows+'</tbody></table></div>'+
  '<p class="hint">轮换期间可继续分发与下载。全部归档换密且无在途读写后，旧密钥才可退役；退役后原密文不可解读。分析员与观察员只能查看。</p></section>';
}

function rotationPanel(data){
 const rows=data.rotations.map(r=>'<article><div><strong>向 v'+r.target_version+' 迁移</strong><p>'+esc(ROTATION_STATUS[r.status]||r.status)+' · 完成 '+r.done+' / 待处理 '+r.pending+' / 失败 '+r.failed+'</p><small>发起 '+esc(r.created_by)+' · '+date(r.created_at)+'</small></div><span class="status">'+r.total+' 份</span></article>').join('')||'<p class="empty">尚未发起轮换。归档使用当前生效密钥保存。</p>';
 return '<section class="panel"><div class="section-title"><h2>迁移批次</h2><span>中断后可恢复，重试不会重复迁移</span></div><div class="schedule-list">'+rows+'</div></section>';
}

function inbox(deliveries,data){
 const versions=new Map(data.keys.map(k=>[k.version,k]));
 return '<section class="panel inbox"><div class="section-title"><h2>本地收件箱</h2><span>'+deliveries.length+' 份归档 · 静态加密</span></div>'+
  deliveries.map(d=>{
   const state={pending:'待迁移',migrating:'迁移中',failed:'迁移失败',done:'已加密'}[d.encryption_state]||d.encryption_state;
   const owner=d.key_version?('v'+d.key_version):'明文';
   const key=d.key_version?versions.get(d.key_version):null;
   const readable=!d.key_version||(d.key_available&&(!key||key.status!=='retired'));
   return '<div class="delivery"><div><strong>'+esc(d.filename)+'</strong><p>'+esc(d.destination)+' · '+date(d.created_at)+'</p><small>SHA256 '+esc(d.checksum.slice(0,24))+'… · 密钥 '+esc(owner)+' · '+esc(state)+(d.error?' · '+esc(d.error):'')+'</small></div><div>'+
    (readable?'<button class="text-button" data-download="'+d.id+'" data-format="csv">CSV ↓</button><button class="text-button" data-download="'+d.id+'" data-format="json">JSON ↓</button>':'<span class="hint">密钥已退役，不可下载</span>')+
    '</div></div>';
  }).join('')+(deliveries.length?'':'<p class="empty">计划执行后，文件会出现在此处。等待片刻后刷新。</p>')+'</section>';
}

export async function reportPage(){
 const [list,deliveries,allJobs,data]=await Promise.all([reports.list(),reports.deliveries(),jobs.list(),archiveKeys.overview()]);workspace.reports=list;
 const approved=allJobs.filter(j=>j.approved&&j.status==='completed');
 return heading('05 / DISTRIBUTION','定时分发与归档加密','把批准后的结果交付到本地业务收件箱。归档静态加密，密钥由业务负责人独立保管并可轮换。','<button class="button" id="refresh-reports">刷新收件箱 ↻</button>')+'<div class="report-grid"><section class="panel"><div class="section-title"><h2>创建分发计划</h2></div><form id="report-form"><label>简报名称<input name="name" required minlength="2" value="日间业务复核简报"></label><label>已批准分析<select name="job_id" required>'+approved.map(j=>'<option value="'+j.id+'">'+esc(j.name)+'</option>').join('')+'</select></label><label>业务接收组<input name="destination" value="业务复核组 · 本地收件箱" required></label><div class="parameter-grid"><label>分发周期<select name="interval_seconds"><option value="86400">每日</option><option value="604800">每周</option><option value="60">每分钟（验收）</option></select></label><label>首次执行<select name="delay_seconds"><option value="0">立即</option><option value="60">1 分钟后</option><option value="3600">1 小时后</option></select></label></div><button type="submit" class="primary" '+(session.user.role!=='admin'||!approved.length?'disabled':'')+'>保存分发计划</button></form><p class="hint">由后台 worker 按到期时间生成文件。仅负责人可创建或暂停；接收组为本地标签。</p></section><section><div class="section-title"><h2>运行中的计划</h2><span>'+list.filter(r=>r.enabled).length+' 条已启用</span></div><div class="schedule-list">'+list.map(r=>'<article><div><strong>'+esc(r.name)+'</strong><p>'+esc(r.destination)+'</p><small>下次 '+date(r.next_run)+' · 周期 '+r.interval_seconds+' 秒</small></div><button class="button small" data-toggle="'+r.id+'" '+(session.user.role!=='admin'?'disabled':'')+'>'+(r.enabled?'暂停':'启用')+'</button></article>').join('')+'</div>'+inbox(deliveries,data)+'</section></div>'+
  '<div class="report-grid"><section>'+keyPanel(data)+'</section><section>'+rotationPanel(data)+'</section></div>';
}
export function bindReports(refresh){document.querySelector('#refresh-reports').onclick=refresh;submit(document.querySelector('#report-form'),async f=>{await reports.create({name:f.get('name'),job_id:Number(f.get('job_id')),destination:f.get('destination'),interval_seconds:Number(f.get('interval_seconds')),delay_seconds:Number(f.get('delay_seconds'))});notify('计划已保存，后台将按到期时间归档');await refresh();});document.querySelectorAll('[data-toggle]').forEach(b=>b.onclick=async()=>{try{await reports.toggle(b.dataset.toggle);await refresh();}catch(e){notify(e.message,true);}});document.querySelectorAll('[data-download]').forEach(b=>b.onclick=()=>download(b.dataset.download,b.dataset.format).catch(e=>notify(e.message,true)));
 document.querySelector('#rotate-keys').onclick=async()=>{if(!confirm('发起密钥轮换？存量归档将在后台逐步换密，期间仍可下载。'))return;try{await archiveKeys.rotate();notify('已发起轮换，后台开始迁移存量归档');await refresh();}catch(e){notify(e.message,true);}};
 document.querySelector('#migrate-now').onclick=async()=>{try{const r=await archiveKeys.migrate(false);notify('本轮迁移 '+r.migrated+' 份');await refresh();}catch(e){notify(e.message,true);}};
 document.querySelector('#retry-failed').onclick=async()=>{try{const r=await archiveKeys.migrate(true);notify('已重试 '+r.retried+' 份失败项');await refresh();}catch(e){notify(e.message,true);}};
 document.querySelectorAll('[data-retire]').forEach(b=>b.onclick=async()=>{if(!confirm('退役 v'+b.dataset.retire+' 密钥后，旧密文将不可解读。确认全部归档已换密？'))return;try{await archiveKeys.retire(b.dataset.retire);notify('旧密钥已退役');await refresh();}catch(e){notify(e.message,true);}});}
