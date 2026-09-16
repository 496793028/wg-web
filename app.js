/* =====================================================================
 *  VPN 权限管控平台 —— 前端
 *  连接 server/ 的 REST API，所有鉴权与权限校验均由服务端强制执行。
 *  后端不可达时显示可读错误提示，不再降级为本地演示数据。
 * ===================================================================== */
'use strict';
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function esc(s){ return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }
const uid = p => p + '_' + Math.random().toString(36).slice(2, 9);
/* 生成强随机初始口令（满足服务端策略：≥6 位且含大小写与数字）。
   字符集刻意避开 & < > " ' ，避免写入 HTML 属性时需转义。 */
function randPwd(len=16){
  const U='ABCDEFGHJKLMNPQRSTUVWXYZ', L='abcdefghijkmnopqrstuvwxyz', D='23456789', S='!@#$%^*-_=+';
  const all=U+L+D+S, buf=new Uint32Array(1);
  const rnd=n=>{ const lim=Math.floor(4294967296/n)*n; let x;
    do{ crypto.getRandomValues(buf); x=buf[0]; }while(x>=lim); return x%n; };   // 拒绝采样，无模偏差
  const out=[U[rnd(U.length)],L[rnd(L.length)],D[rnd(D.length)],S[rnd(S.length)]];
  while(out.length<len) out.push(all[rnd(all.length)]);
  for(let i=out.length-1;i>0;i--){ const j=rnd(i+1); [out[i],out[j]]=[out[j],out[i]]; }
  return out.join('');
}
function fmt(ts){ const d = new Date(ts), p = n => String(n).padStart(2,'0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; }
const svc = p => ({22:'SSH',53:'DNS',80:'HTTP',443:'HTTPS',445:'SMB',1433:'MSSQL',3306:'MySQL',
  3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',9200:'ES',27017:'MongoDB'}[p] || '-');
/* 端口规格展示：'' = 全部端口；否则原样显示（如 80 / 100-200 / 9,100-200） */
const portText = p => (p === '' || p == null) ? '所有端口' : String(p);
/* 服务名仅在单端口时给出，区间/多段/全部不适用 */
const svcOf = p => /^\d+$/.test(String(p == null ? '' : p)) ? svc(Number(p)) : '—';
function ago(ts){ const s=(Date.now()-ts)/1000;
  if(s<60) return '刚刚'; if(s<3600) return Math.floor(s/60)+' 分钟前';
  if(s<86400) return Math.floor(s/3600)+' 小时前'; if(s<2592000) return Math.floor(s/86400)+' 天前';
  return fmt(ts).slice(0,10); }

function toast(msg, type='ok'){
  const el=document.createElement('div'); el.className='toast '+type; el.textContent=msg;
  $('#toastWrap').appendChild(el);
  setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateX(24px)'; },2300);
  setTimeout(()=>el.remove(),2700);
}
const closeLayer = () => { $('#layer').innerHTML=''; };

const ICON = {
  account:'<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6l7-3z"/></svg>',
  dest:'<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>',
  vpn:'<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3.5"/></svg>',
  audit:'<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
  search:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.6-3.6"/></svg>',
  check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4L19 7"/></svg>',
  arrow:'<svg class="combo-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M6 9l6 6 6-6"/></svg>',
  person:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/></svg>',
  gear:'<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  expand:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 6l5 6-5 6M6 6l5 6-5 6"/></svg>',
  reload:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>',
  upload:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M7 9l5-5 5 5"/><path d="M5 20h14"/></svg>',
  logout:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 12H3M11 8l-4 4 4 4"/><path d="M9 4h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H9"/></svg>',
  sun:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
  eye:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 10.7a3 3 0 0 0 4.2 4.2"/><path d="M9.9 5.2A9.6 9.6 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.3 4M6.1 6.1A17 17 0 0 0 2 12s3.5 7 10 7a9.6 9.6 0 0 0 3-.5"/></svg>',
  more:'<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.9"/><circle cx="12" cy="12" r="1.9"/><circle cx="12" cy="19" r="1.9"/></svg>',
};

const MODULES = [
  { k:'account', n:'账号管理', d:'管理系统登录账号，并分配各模块的可见/可改权限' },
  { k:'dest',    n:'目的地池', d:'维护 IP-端口池，并组合成可复用的目的地包' },
  { k:'vpn',     n:'VPN配置',  d:'按真实姓名分配 VPN 账号，授予可访问的目的地' },
  { k:'audit',   n:'访问追踪', d:'查询历史访问记录与管理员操作审计' },
];
const PERM_LABEL = { none:'无权限', r:'仅查看', rw:'可修改' };
const ROLES = { admin:'超级管理员', sec:'安全审计员', op:'运维操作员', custom:'自定义' };

/* ---------------- 状态 ---------------- */
let S = { accounts:[], pools:[], packages:[], vpn:[], logs:[], audits:[], stats:{} };
let me = null, needSetup = false, appErr = '';   // needSetup：首次部署、admin 口令尚未设置
const ui = { route:'account', sel:'account', destTab:'pool', auditTab:'access', batch:false, picked:new Set(),
  editGrants:[], f:{ name:'', dst:'', port:'', act:'', days:'' }, q:{ vpn:'', pool:'', pkg:'', grant:'' }, dockOpen:false };
const canView = m => !!me && (me.role==='admin' || (me.perm && me.perm[m] && me.perm[m]!=='none'));
const canEdit = m => !!me && (me.role==='admin' || (me.perm && me.perm[m]==='rw'));

/* ---------------- 主题（黑白双色，持久化） ---------------- */
let THEME = localStorage.getItem('vpn_theme') || 'dark';
function setTheme(t){
  THEME = t;
  document.body.classList.toggle('theme-light', t==='light');
  document.body.classList.toggle('theme-dark',  t!=='light');
  localStorage.setItem('vpn_theme', t);
}

/* ---------------- 记忆上次停留的页面（刷新后回到原页，而非默认页） ---------------- */
const UI_KEY = 'vpn_ui';
function saveUi(){
  try{ localStorage.setItem(UI_KEY, JSON.stringify({
    route: ui.route, sel: ui.sel, destTab: ui.destTab, auditTab: ui.auditTab })); }catch(e){}
}
function loadUi(){
  try{ const o = JSON.parse(localStorage.getItem(UI_KEY) || '{}');
    return (o && typeof o === 'object') ? o : {}; }catch(e){ return {}; }
}

/* ---------------- API ---------------- */
async function api(method, path, body){
  const opt = { method, credentials:'same-origin', headers:{ 'X-Requested-With':'fetch' } };
  if (body !== undefined){ opt.headers['Content-Type']='application/json'; opt.body=JSON.stringify(body); }
  let r;
  try { r = await fetch('api/'+path, opt); }
  catch (e){ throw new Error('无法连接后端服务，请确认 server 已启动（node server.js）'); }
  let j=null; try{ j=await r.json(); }catch{}
  if (r.status===401){
    const had = !!me;          // 是否此前已登录（会话中途失效才提示）
    me=null; render();
    if(had) throw new Error('会话已失效，请重新登录');
    /* 未登录状态下收到 401（如启动时 auth/me 探测）：视为「尚未登录」，由调用方静默处理 */
    throw new Error('未登录');
  }
  if (!r.ok) throw new Error((j&&j.error)||('请求失败 (HTTP '+r.status+')'));
  return j;
}
async function loadState(){
  const s = await api('GET','state');
  me = s.me;
  S.accounts = (s.accounts||[]).map(a=>({...a, perm:{account:a.perm_account,dest:a.perm_dest,vpn:a.perm_vpn,audit:a.perm_audit}}));
  S.pools = s.pools||[]; S.packages = s.packages||[];
  S.vpn = (s.vpn||[]).map(v=>({...v, ip:v.vpn_ip}));
  await loadAudits();
}
async function loadAudits(){
  if(!canView('audit')) return;
  try{
    const r = await api('GET','audit');
    S.audits = (r.rows||[]).map(a=>({...a, ts:new Date(String(a.ts).replace(' ','T'))}));
  }catch{ S.audits = S.audits || []; }
}
const flatPerm = p => ({ perm_account:p.account, perm_dest:p.dest, perm_vpn:p.vpn, perm_audit:p.audit });

/* ---------------- 组件：搜索框 ---------------- */
const SF = {};
function sfield(id, value, onInput, ph){
  SF[id]=onInput;
  return `<div class="sfield ${value?'has':''}" data-sf="${id}">
    ${ICON.search}
    <input id="${id}" value="${esc(value)}" placeholder="${esc(ph||'搜索…')}" autocomplete="off">
    <button class="s-clear" data-act="sclear" data-t="${id}" type="button">×</button>
    <i class="s-pulse"></i></div>`;
}
function bindSF(){
  $$('[data-sf]').forEach(w=>{
    const i = w.querySelector('input'); if(!i || i._b) return; i._b=1;
    i.oninput = ()=>{ w.classList.toggle('has', !!i.value); const f=SF[w.dataset.sf]; if(f) f(i.value); };
  });
}

/* ---------------- 组件：可搜索下拉 ---------------- */
const COMBOS = {};
function combo(id, cfg){
  COMBOS[id] = cfg;
  const cur = cfg.options.find(o=>String(o.v)===String(cfg.value));
  return `<div class="field">${cfg.label?`<label>${esc(cfg.label)}</label>`:''}
    <div class="combo" data-combo="${id}">
      <button type="button" class="combo-ctl" data-act="combo-toggle">
        <span class="combo-val ${cur?'':'ph'}">${cur?esc(cur.t):esc(cfg.ph||'请选择')}</span>${ICON.arrow}
      </button></div></div>`;
}
function comboOpts(id, q){
  const c = COMBOS[id], qq = (q||'').trim().toLowerCase();
  const list = !qq ? c.options : c.options.filter(o=>(o.t+' '+(o.s||'')).toLowerCase().includes(qq));
  if(!list.length) return '<div class="combo-none">无匹配结果</div>';
  return list.map(o=>`<div class="combo-opt ${String(o.v)===String(c.value)?'sel':''}"
    data-act="combo-pick" data-v="${esc(o.v)}"><i class="co-dot"></i>
    <span>${esc(o.t)}</span>${o.s?`<span class="co-sub" style="margin-left:auto">${esc(o.s)}</span>`:''}</div>`).join('');
}
function comboPop(id){
  const c = COMBOS[id];
  return `<div class="combo-pop">${
    c.searchable===false ? '' : `<div class="combo-search">${sfield('cbq_'+id,'',v=>{
      const l=document.getElementById('cbl_'+id); if(l) l.innerHTML=comboOpts(id,v); },'搜索…')}</div>`}
    <div class="combo-list" id="cbl_${id}">${comboOpts(id,'')}</div></div>`;
}
function closeCombos(except){
  $$('.combo.open').forEach(c=>{ if(c===except) return;
    c.classList.remove('open'); const p=c.querySelector('.combo-pop'); if(p) p.remove(); });
}

/* ---------------- 数据助手 ---------------- */
const pool = id => S.pools.find(p=>String(p.id)===String(id));
const pkg  = id => S.packages.find(p=>String(p.id)===String(id));
const acct = id => S.accounts.find(a=>String(a.id)===String(id));
const vuser= id => S.vpn.find(v=>String(v.id)===String(id));
function colorOf(n){ const cs=['#4c8dff','#2ecc8f','#a78bfa','#f5b544','#f4636b','#38bdf8','#fb7185','#34d399'];
  let h=0; for(const c of String(n)) h=(h*31+c.charCodeAt(0))>>>0; return cs[h%cs.length]; }
function grantTags(v){
  return v.grants.map(g=>{
    if(g.t==='pool'){ const p=pool(g.id); return p && {cls:'pool',t:p.name,s:`${p.ip}:${p.port}`}; }
    const k=pkg(g.id); return k && {cls:'pkg', t:k.name,s:`含 ${k.poolIds.length} 项`};
  }).filter(Boolean);
}
const grantCount = v => v.grants.reduce((n,g)=> n + (g.t==='pool' ? 1 : (pkg(g.id)?pkg(g.id).poolIds.length:0)), 0);
/* 授权目的地签名：用于判断「保存后客户端 AllowedIPs 是否会变」——模式切换或目的地增删都算变化 */
const grantSig = g => (g||[]).map(x=>`${x.t}:${x.id}`).sort().join('|');

/* ---------------- 渲染入口 ---------------- */
function render(){
  const app = $('#app');
  if(appErr){ app.innerHTML = `<div class="login-wrap"><div class="login-card" style="text-align:center">
    <div class="login-brand"><div class="logo">${LOGO_SVG}</div>
      <div><h1>VPN 权限管控平台</h1><p>VPN ACCESS CONTROL</p></div></div>
    <div class="demo-banner" style="margin-top:18px"><div>${esc(appErr)}</div></div>
    </div></div>`; return; }
  if(needSetup){ app.innerHTML = setupHTML(); bindSF(); const f=$('#setupForm'); if(f) f.onsubmit = doSetup; return; }
  if(!me){ app.innerHTML = loginHTML(); bindSF(); const f=$('#loginForm'); if(f) f.onsubmit = doLogin; return; }
  app.innerHTML = shell();
  document.body.classList.toggle('dock-open', ui.dockOpen);
  bindSF();
  requestAnimationFrame(()=>{ moveCursorTo(); moveMbarCursor(); moveTabCursors(); if(ui.route==='audit'){ bindLogFilters(); loadLogs(); } });
}
function refresh(){ const m=$('#mainView'); if(m){ m.innerHTML = `<div class="view">${routeView()}</div>`; bindSF();
  requestAnimationFrame(moveTabCursors);
  if(ui.route==='audit'){ bindLogFilters(); loadLogs(); } } }

/* 品牌图标：登录页与初始化页共用，避免两处各写一份 SVG */
const LOGO_SVG = `<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>`;

function loginHTML(){
  return `<div class="login-wrap"><div class="login-card">
    <button class="login-theme" data-act="theme-toggle" title="切换黑白风格">${THEME==='light'?ICON.moon:ICON.sun}</button>
    <div class="login-brand"><div class="logo">${LOGO_SVG}</div>
      <div><h1>VPN 权限管控平台</h1><p>VPN ACCESS CONTROL</p></div></div>
    <form id="loginForm" autocomplete="off">
      <div class="field"><label>管理员账号</label>
        <input name="u" autocomplete="username" placeholder="登录账号"></div>
      <div class="field"><label>登录密码</label>
        <input name="p" type="password" autocomplete="current-password" placeholder="密码"></div>
      <div class="login-err" id="loginErr"></div>
      <button class="btn primary block" type="submit">登 录</button></form>
    <div style="text-align:center;margin-top:14px">
      <span class="badge ok">● 已连接后端服务</span></div>
  </div></div>`;
}

/* 首次部署：admin 口令未设置时显示，引导在网页上设定初始口令。
   这样源码里不存在任何固定的默认口令，初始口令也不会出现在日志/终端历史里。 */
function setupHTML(){
  return `<div class="login-wrap"><div class="login-card">
    <button class="login-theme" data-act="theme-toggle" title="切换黑白风格">${THEME==='light'?ICON.moon:ICON.sun}</button>
    <div class="login-brand"><div class="logo">${LOGO_SVG}</div>
      <div><h1>初始化管理员口令</h1><p>FIRST-TIME SETUP</p></div></div>
    <p class="setup-desc">系统尚未设置管理员口令。请为超级管理员账号 <code>admin</code>
      设定一个强口令，设定完成后即可直接进入平台。</p>
    <form id="setupForm" autocomplete="off">
      ${pwField('新口令','p',{ac:'new-password', ph:'至少 6 位，含大小写字母与数字'})}
      ${pwField('确认口令','p2',{ac:'new-password', ph:'再次输入相同口令', last:true})}
      <div class="login-err" id="setupErr"></div>
      <button class="btn primary block" type="submit">设定口令并进入</button></form>
    <div class="demo-tip"><b>口令要求</b>：至少 6 位，且同时包含大写字母、小写字母与数字。<br>
      本页面仅在口令未设置时出现；设定后请妥善保管，遗失只能通过服务器端重置。</div>
  </div></div>`;
}
async function doSetup(e){
  e.preventDefault();
  const f = e.target, err = $('#setupErr');
  const p = f.p.value, p2 = f.p2.value;
  if(p !== p2){ if(err) err.textContent = '两次输入的口令不一致'; return; }
  if(err) err.textContent = '';
  try{
    await api('POST','auth/setup',{ password:p });
    needSetup = false;
    await loadState();
    ui.route = (MODULES.find(m=>canView(m.k))||MODULES[0]).k; ui.sel = ui.route;
    render(); toast('初始口令已设置');
  }catch(ex){ if(err) err.textContent = ex.message; }
}

async function doLogin(e){
  e.preventDefault();
  const login = e.target.u.value.trim(), pwd = e.target.p.value, err = $('#loginErr');
  try{
    await api('POST','auth/login',{login,password:pwd});
    await loadState();
    ui.route = (MODULES.find(m=>canView(m.k))||MODULES[0]).k; ui.sel=ui.route;
    ui.batch=false; ui.picked.clear();
    render(); toast(`欢迎回来，${me.name}`);
  }catch(ex){
    /* 后端提示「初始口令尚未设置」：说明本页在初始化完成前被打开过，直接切到初始化页 */
    if(/尚未设置/.test(ex.message||'')){
      try{ const st = await api('GET','auth/setup-status'); if(st && st.needSetup){ needSetup = true; render(); return; } }catch{}
    }
    err.textContent = ex.message || '登录失败';
    err.style.animation='none'; void err.offsetWidth; err.style.animation=''; }
}

/* ================= Dock（分层侧栏）================= */
function avatarURL(){
  if(!me || !me.avatar) return null;
  return me.avatar; // 真实模式下为 /uploads/avatars/.. 路径
}
function navItems(){
  const arr = MODULES.filter(m=>canView(m.k)).map(m=>({ k:m.k, sel:m.k, n:m.n, ico:ICON[m.k] }));
  if(me.role==='admin' || canEdit('account')) arr.push({ k:'settings', sel:'gear', n:'设置', ico:ICON.gear });
  return arr;
}
function currentPathName(){
  if(ui.route==='settings') return '设置';
  return (MODULES.find(m=>m.k===ui.route)||{n:'权限设置'}).n;
}
function shell(){
  const items = navItems();
  const navHtml = items.map(it=>`
    <button class="dock-item ${ui.sel===it.sel?'sel':''}" data-act="nav" data-k="${it.k}" data-sel="${it.sel}">
      <span class="di-ico">${it.ico}</span>
      <span class="di-label">${it.n}</span>
      ${it.k!=='settings' && !canEdit(it.k)?`<span class="ro-tag">只读</span>`:''}
    </button>`).join('');
  const av = avatarURL();
  const dock = `<div class="dock" id="dock"><div class="dock-rail">
    <div class="dock-idwrap" data-act="avatar-toggle" id="dockAvatarWrap" title="${esc(me.name)}">
      <button class="dock-avatar" id="dockAvatar" type="button">
        ${av?`<img src="${esc(av)}" alt="">`:ICON.person}</button>
      <div class="dock-user"><div class="du-name">${esc(me.name)}</div><div class="du-role">${esc(ROLES[me.role]||me.role)}</div></div>
    </div>
    <nav class="dock-nav" id="dockNav">
      <div class="dock-cursor" id="dockCursor"></div>
      ${navHtml}
    </nav>
    <button class="dock-expand" data-act="dock-toggle" title="展开 / 收起">${ICON.expand}</button>
  </div></div>`;
  const mbar = `<div class="mbar"><div class="mbar-cursor" id="mbarCursor"></div>${items.map(it=>`
    <button class="mbar-item ${ui.sel===it.sel?'sel':''}" data-act="nav" data-k="${it.k}" data-sel="${it.sel}">
      <span class="mb-ico">${it.ico}</span><span class="mb-label">${it.n}</span></button>`).join('')}</div>`;
  const mtop = `<div class="mtop">
      <button class="mtop-avatar" data-act="avatar-toggle" type="button" title="${esc(me.name)}">
        ${av?`<img src="${esc(av)}" alt="">`:ICON.person}</button>
      <div class="mtop-title">${esc(currentPathName())}</div>
      <button class="icon-btn" data-act="reload" title="刷新数据">${ICON.reload}</button>
    </div>`;
  const main = `<div class="main">
    <div class="topstrip">
      <span class="badge ok">● 后端已连接</span>
      <span class="strip-path">当前：<b>${esc(currentPathName())}</b></span>
      <span class="spacer"></span>
      <button class="icon-btn" data-act="reload" title="刷新数据">${ICON.reload}</button>
    </div>
    <div id="mainView"><div class="view">${routeView()}</div></div>
  </div>`;
  return dock + mtop + mbar + main;
}

/* 高亮块「首次定位」必须瞬移就位：整屏重渲染后元素是全新的，若直接设值，
   它会从 CSS 初始位置（0 / 左上角）过渡过来，看起来像「从外部飞入」。
   首帧之后的变化才走过渡动画（滑动效果）。 */
function placeCursor(el, apply){
  if(!el._placed){ el._placed=1; el.style.transition='none'; apply(); void el.offsetWidth; el.style.transition=''; }
  else apply();
}
function moveCursorTo(){
  const cur = document.getElementById('dockCursor'); if(!cur) return;
  const el = document.querySelector('.dock-item.sel'); if(!el) return;
  const cs = getComputedStyle(document.body);
  const rail = parseFloat(cs.getPropertyValue('--rail')) || 80;
  const labels = parseFloat(cs.getPropertyValue('--labels')) || 0;
  placeCursor(cur, ()=>{
    cur.style.width = (rail + labels - 28) + 'px';   // 自定义属性即时翻转，取目标宽度（不受过渡动画影响）
    cur.style.transform = `translateY(${el.offsetTop}px)`;
  });
}
/* 竖屏底栏：滑动圆角方形高亮，跟随选中项平移（与侧栏 .dock-cursor 同款动画 + 颜色变化） */
function moveMbarCursor(){
  const cur = document.getElementById('mbarCursor'); if(!cur) return;
  const bar = cur.parentElement; if(!bar) return;
  const el = bar.querySelector('.mbar-item.sel'); if(!el) return;
  const br = bar.getBoundingClientRect(), er = el.getBoundingClientRect();
  placeCursor(cur, ()=>{
    cur.style.width = er.width + 'px';
    cur.style.height = er.height + 'px';
    cur.style.transform = `translate(${er.left - br.left - bar.clientLeft}px, ${er.top - br.top - bar.clientTop}px)`;
  });
}
/* 横竖屏切换 / 窗口尺寸变化后必须重新量一次两个滑动高亮：
   竖屏时侧栏 display:none、横屏时底栏 display:none，隐藏元素的 offset/rect 全是 0，
   不重算就会出现「横屏翻页后切竖屏 → 底栏高亮错位/消失」「竖屏翻页后切横屏 → 侧栏高亮错位」。 */
let cursorRaf=0;
function relayoutCursors(){
  cancelAnimationFrame(cursorRaf);
  cursorRaf=requestAnimationFrame(()=>{ moveCursorTo(); moveMbarCursor(); moveTabCursors(); });
}
addEventListener('resize', relayoutCursors);
addEventListener('orientationchange', ()=>setTimeout(relayoutCursors, 160));   // 等视口尺寸稳定再量
/* 竖屏与横屏的呈现方式不同（部分页面竖屏走卡片、横屏走表格），
   因此「是否移动端」真正翻转时才重渲染一次（普通 resize 不触发，避免频繁重绘）。 */
matchMedia('(max-width: 760px), (orientation: portrait) and (max-width: 900px)')
  .addEventListener('change', ()=>{ if(me) refresh(); });

/* 标签页（分段控件）的滑动高亮：与侧栏 / 底栏同款「圆角高亮滑过去」。
   切标签会整屏重渲染，游标元素是全新的、CSS 无法自动从旧位置过渡，所以用 FLIP。
   ⚠️ 起点必须记「相对容器的偏移」，不能用视口坐标：切换标签时整块标签行的纵向位置会变
   （两个分支标题区高度不同），若用视口坐标再减新容器位置，起点就会算到容器外，
   看起来像「从左上角飞入」。 */
let tabFlipFrom=null;
function rememberTabCursor(){
  const cur=document.querySelector('.tabs .tabs-cursor'); if(!cur) return;
  const tb=cur.parentElement; if(!tb) return;
  const r=cur.getBoundingClientRect(), b=tb.getBoundingClientRect();
  if(r.width) tabFlipFrom={ x:r.left-b.left-tb.clientLeft, y:r.top-b.top-tb.clientTop, w:r.width, h:r.height };
}
function moveTabCursors(){
  document.querySelectorAll('.tabs').forEach(tb=>{
    const cur=tb.querySelector('.tabs-cursor'), on=tb.querySelector('.tab.on');
    if(!cur || !on) return;
    const w=on.offsetWidth, h=on.offsetHeight; if(!w) return;
    const br=tb.getBoundingClientRect();
    const x=on.getBoundingClientRect().left - br.left - tb.clientLeft;
    const y=on.getBoundingClientRect().top  - br.top  - tb.clientTop;
    if(tabFlipFrom){
      const f=tabFlipFrom; tabFlipFrom=null; cur._placed=1;
      cur.style.transition='none';                       // 先瞬移回旧位置（相对容器）
      cur.style.width=f.w+'px'; cur.style.height=f.h+'px';
      cur.style.transform=`translate(${f.x}px, ${y}px)`; // 纵向直接用目标位置 → 只做纯水平滑动，绝不「从上方飞入」
      void cur.offsetWidth;                              // 强制回流：把旧位置落定为过渡起点
      cur.style.transition='';
    }
    placeCursor(cur, ()=>{
      cur.style.width=w+'px'; cur.style.height=h+'px';
      cur.style.transform=`translate(${x}px, ${y}px)`;
    });
  });
}

/* 头像下拉菜单 */
function toggleAvatarMenu(src){
  const old = document.getElementById('avatarMenu'); if(old){ old.remove(); return; }
  const a = (src && document.body.contains(src)) ? src : document.getElementById('dockAvatar'); if(!a) return;
  const r = a.getBoundingClientRect();
  const m = document.createElement('div'); m.className='avatar-menu'; m.id='avatarMenu';
  m.innerHTML = `<div class="am-head"><div class="am-name">${esc(me.name)}</div><div class="am-role">${esc(ROLES[me.role]||me.role)}</div></div>
    <div class="am-theme"><span class="am-theme-label">${ICON.sun}<span>黑白风格</span></span>
      <button class="am-switch ${THEME==='light'?'on':''}" data-act="theme-toggle" role="switch" aria-checked="${THEME==='light'}">
        <span class="am-knob"></span></button></div>
    <button class="am-item" data-act="self-pw">${ICON.person}<span>修改密码</span></button>
    <button class="am-item" data-act="avatar-edit">${ICON.upload}<span>修改头像</span></button>
    <button class="am-item danger" data-act="logout">${ICON.logout}<span>退出登录</span></button>`;
  document.body.appendChild(m);
  const mw = m.offsetWidth;
  let left = Math.min(r.right - mw + 16, window.innerWidth - mw - 10);
  if(left < 10) left = 10;
  m.style.left = left + 'px';
  m.style.top  = (r.bottom + 10) + 'px';
  requestAnimationFrame(()=>m.classList.add('open'));
  setTimeout(()=>document.addEventListener('click', avatarOutside), 0);
}
function avatarOutside(e){
  if(!e.target.closest('.avatar-menu') && !e.target.closest('[data-act="avatar-toggle"]')){
    const m=document.getElementById('avatarMenu'); if(m) m.remove();
    document.removeEventListener('click', avatarOutside);
  }
}
async function uploadAvatar(dataURL){
  try{
    const r = await api('POST','me/avatar',{data:dataURL}); me.avatar = r.avatar;
    document.getElementById('avatarMenu')?.remove();
    render();
    toast('头像已更新');
  }catch(e){ toast(e.message,'err'); }
}

/* ================= 路由视图 ================= */
function isMobile(){
  return window.matchMedia('(max-width: 760px), (orientation: portrait) and (max-width: 900px)').matches;
}
/* 二级菜单（modal/drawer）内存在未保存输入（搜索框除外）时，移动端点击遮罩不关闭 */
function layerHasUnsavedInput(){
  const layer=$('#layer'); if(!layer) return false;
  return [...layer.querySelectorAll('input,textarea,select')].some(el=>{
    if(el.closest('.sfield, .combo-search')) return false;
    return (el.value||'').trim() !== '';
  });
}
/* 条目（表格行 / 卡片）：竖屏下点击整条即在点击位置弹出操作选单；横屏保留操作列按钮。 */
function rowActsAttr(acts){ return ` data-rowacts='${JSON.stringify(acts)}'`; }
function openActionMenu(anchor, acts, pt){
  document.getElementById('popMenu')?.remove();
  const m = document.createElement('div'); m.className='avatar-menu pop-menu'; m.id='popMenu';
  m.innerHTML = (acts||[]).map(a=>`<button class="am-item ${a.danger?'danger':''}" data-act="${a.act}" data-id="${a.id}" ${a.disabled?'disabled':''}>${esc(a.label)}</button>`).join('')
    || '<div class="am-item" style="color:var(--faint)">无可执行操作</div>';
  document.body.appendChild(m);
  const mw=m.offsetWidth, mh=m.offsetHeight;
  let left, top, refTop;
  if(pt){                                   // 点击条目触发：在点击位置弹出
    left=pt.x; refTop=pt.y; top=pt.y + 6;
  }else{                                    // 「更多」按钮触发：贴着按钮右下弹出
    const r=anchor.getBoundingClientRect();
    left=r.right - mw; refTop=r.top; top=r.bottom + 8;
  }
  left=Math.max(8, Math.min(left, window.innerWidth - mw - 8));
  if(top + mh > window.innerHeight - 8) top=Math.max(8, refTop - mh - 8);
  m.style.left=left+'px'; m.style.top=top+'px';
  requestAnimationFrame(()=>m.classList.add('open'));
  m.addEventListener('click', e=>{ if(e.target.closest('[data-act]')) m.remove(); });
  document.addEventListener('click', popOutside, true);
}
function popOutside(e){
  if(!e.target.closest('.pop-menu')){
    document.getElementById('popMenu')?.remove();
    document.removeEventListener('click', popOutside, true);
  }
}
/* 修改头像：选图 → 校验可渲染 → 圆形蒙版预览（缩放 / 拖动 / 双指）→ 提交方形裁切 */
function openAvatarCrop(dataURL){
  const img = new Image();
  img.onload = ()=>{ buildCropUI(img, dataURL); };
  img.onerror = ()=> toast('图片无法渲染，文件可能已损坏或不是受支持的图片格式','err');
  img.src = dataURL;
}
function buildCropUI(img, dataURL){
  const D=240, OUT=256;
  $('#layer').innerHTML = `<div class="modal-wrap" data-backdrop><div class="crop-modal">
    <div class="modal-hd"><h3>调整头像</h3><button class="icon-btn" data-close>×</button></div>
    <div class="crop-stage" id="cropStage">
      <img id="cropImg" src="${dataURL}" alt="">
      <div class="crop-mask" style="width:${D}px;height:${D}px"></div>
      <div class="crop-hint">滚轮 / 双指缩放 · 拖动调整位置</div>
    </div>
    <div class="modal-ft"><button class="btn" data-close>取消</button>
      <button class="btn primary" id="cropSubmit">提交</button></div>
  </div></div>`;
  const stage=$('#cropStage'), im=$('#cropImg');
  const W=img.naturalWidth, H=img.naturalHeight;
  const minScale=D/Math.max(W,H), maxScale=12;
  let scale=Math.min(maxScale, Math.max(minScale, D/Math.min(W,H)));
  let imgX=stage.clientWidth/2 - W/2*scale, imgY=stage.clientHeight/2 - H/2*scale;
  const clamp=v=>Math.max(minScale, Math.min(maxScale, v));
  function apply(){ im.style.transform=`translate(${imgX}px,${imgY}px) scale(${scale})`; }
  function zoomAt(fx, fy, ns){ ns=clamp(ns);
    imgX=fx-(fx-imgX)*(ns/scale); imgY=fy-(fy-imgY)*(ns/scale); scale=ns; apply(); }
  apply();
  const pointers=new Map(); let lastX=0,lastY=0,lastDist=0,dragging=false;
  stage.addEventListener('pointerdown', e=>{ stage.setPointerCapture?.(e.pointerId);
    pointers.set(e.pointerId,{x:e.clientX,y:e.clientY});
    if(pointers.size===1){ dragging=true; lastX=e.clientX; lastY=e.clientY; } });
  stage.addEventListener('pointermove', e=>{ if(!pointers.has(e.pointerId)) return;
    pointers.set(e.pointerId,{x:e.clientX,y:e.clientY});
    if(pointers.size>=2){ const p=[...pointers.values()]; const d=Math.hypot(p[0].x-p[1].x, p[0].y-p[1].y);
      const mx=(p[0].x+p[1].x)/2, my=(p[0].y+p[1].y)/2, r=stage.getBoundingClientRect();
      if(lastDist) zoomAt(mx-r.left, my-r.top, scale*(d/lastDist)); lastDist=d; }
    else if(dragging){ imgX+=e.clientX-lastX; imgY+=e.clientY-lastY; lastX=e.clientX; lastY=e.clientY; apply(); } });
  const up=e=>{ pointers.delete(e.pointerId); if(pointers.size<2) lastDist=0; if(pointers.size===0) dragging=false; };
  stage.addEventListener('pointerup', up); stage.addEventListener('pointercancel', up);
  stage.addEventListener('wheel', e=>{ e.preventDefault(); const r=stage.getBoundingClientRect();
    zoomAt(e.clientX-r.left, e.clientY-r.top, scale*(e.deltaY<0?1.12:0.89)); }, {passive:false});
  $('#cropSubmit').onclick=()=>{
    const cx=stage.clientWidth/2, cy=stage.clientHeight/2;
    let s=D/scale; s=Math.min(s, W, H);
    const ix=(cx-imgX)/scale, iy=(cy-imgY)/scale;
    const x0=Math.max(0,Math.min(ix-s/2, W-s)), y0=Math.max(0,Math.min(iy-s/2, H-s));
    const c=document.createElement('canvas'); c.width=OUT; c.height=OUT;
    const ctx=c.getContext('2d'); ctx.fillStyle='#fff'; ctx.fillRect(0,0,OUT,OUT);
    ctx.drawImage(img, x0, y0, s, s, 0, 0, OUT, OUT);
    // 以 JPEG 输出并压缩到 256×256，体积仅数十 KB，远小于后端 2MB 上限，
    // 避免原图分辨率过高导致存储与传输浪费（也呼应「5MB 限制过大」的反馈）。
    let out; try{ out=c.toDataURL('image/jpeg', 0.82); }catch{ toast('裁切失败，请重试','err'); return; }
    uploadAvatar(out).finally(closeLayer);
  };
}
function viewSettings(){
  const av = avatarURL();
  const perms = MODULES.map(m=>`<div class="perm-row">
      <span class="perm-mod">${m.n}</span>
      <span class="badge ${me.role==='admin'?'ok':(me.perm[m.k]==='rw'?'ok':me.perm[m.k]==='r'?'warn':'')}">${me.role==='admin'?'可修改':(PERM_LABEL[me.perm[m.k]]||'无权限')}</span>
    </div>`).join('');
  return `<div class="page-hd"><div><div class="page-title">设置</div>
      <div class="page-desc">查看并管理你的个人资料与偏好</div></div></div>
    <div class="settings-grid">
      <div class="panel profile-hero">
        <div class="profile-hero-inner">
          <div class="profile-top">
            <button class="profile-avatar" data-act="avatar-edit" type="button" title="修改头像">
              <span class="pa-thumb">${av?`<img src="${esc(av)}" alt="">`:ICON.person}</span>
              <span class="pa-edit">${ICON.upload}</span>
            </button>
            <div class="profile-meta">
              <div class="profile-name">${esc(me.name)}</div>
              <div class="profile-role">${esc(ROLES[me.role]||me.role)}</div>
              <div class="profile-login sub mono">${esc(me.login)}</div>
            </div>
          </div>
          <div class="pf-row pf-theme"><span class="pf-label">${ICON.sun}<span>黑白风格</span></span>
            <button class="am-switch ${THEME==='light'?'on':''}" data-act="theme-toggle" role="switch" aria-checked="${THEME==='light'}"><span class="am-knob"></span></button></div>
        </div>
        <div class="profile-actions">
          <button class="btn block" data-act="self-pw">${ICON.person}<span>修改密码</span></button>
          <button class="btn block danger" data-act="logout">${ICON.logout}<span>退出登录</span></button>
        </div>
      </div>
      <div class="panel profile-perms-card">
        <div class="pp-hd">我的权限</div>
        <div class="profile-perms">${perms}</div>
      </div>
    </div>`;
}
function routeView(){
  if(ui.route==='settings') return viewSettings();
  if(!canView(ui.route)) return `<div class="empty"><div class="e-ico">🔒</div><p>你没有访问该模块的权限</p></div>`;
  return ({account:viewAccount,dest:viewDest,vpn:viewVpn,audit:viewAudit})[ui.route]();
}

/* ================= 账号管理 ================= */
/* 账号头像：有自定义头像则显示头像图，否则退回「姓名首字」色块（与设置页头像同源） */
function accAvatar(a, size){
  const px = size || 32, url = a.avatar ? `/uploads/avatars/${a.avatar}` : null;
  return `<div class="avatar" style="width:${px}px;height:${px}px;border-radius:${Math.round(px*0.28)}px;font-size:${Math.round(px*0.4)}px;background:${colorOf(a.name)}">${url?`<img src="${esc(url)}" alt="">`:esc(String(a.name||'').slice(0,1))}</div>`;
}
function viewAccount(){
  const ro = !canEdit('account');
  const rows = S.accounts.map(a=>`<tr class="row-click"${rowActsAttr([
      {act:'acct-edit', id:a.id, label: ro?'查看':'编辑'},
      {act:'acct-pw', id:a.id, label:'重置密码', disabled: !!ro},
      {act:'acct-del', id:a.id, label:'删除', danger:true, disabled: !!(ro||a.role==='admin')},
    ])}>
    <td><div style="display:flex;align-items:center;gap:10px">
      ${accAvatar(a)}
      <div><div>${esc(a.name)}</div><div class="sub mono">${esc(a.login)}</div></div></div></td>
    <td><span class="badge ${a.role==='admin'?'acc':''}">${esc(ROLES[a.role]||a.role)}</span></td>
    ${MODULES.map(m=>`<td>${a.role==='admin' ? '<span class="badge ok">可修改</span>'
      : `<span class="badge ${a.perm[m.k]==='rw'?'ok':a.perm[m.k]==='r'?'warn':''}">${PERM_LABEL[a.perm[m.k]]||'无权限'}</span>`}</td>`).join('')}
    <td><span class="badge ${(a.status===1||a.status==='on')?'ok':'danger'}"><i class="dot"></i>${(a.status===1||a.status==='on')?'启用':'停用'}</span></td>
    <td class="sub">${a.last_login_at?ago(a.last_login_at):(a.lastLogin?ago(a.lastLogin):'—')}</td>
    <td class="col-op"><div class="row-acts">
      <button class="btn sm" data-act="acct-edit" data-id="${a.id}">${ro?'查看':'编辑'}</button>
      <button class="btn sm" data-act="acct-pw" data-id="${a.id}" ${ro?'disabled':''}>重置密码</button>
      <button class="icon-btn del" data-act="acct-del" data-id="${a.id}" ${ro||a.role==='admin'?'disabled style="opacity:.25"':''}>×</button>
    </div></td></tr>`).join('');
  /* 竖屏用卡片、横屏用表格（同一份数据的两种呈现；朝向真正变化时由 mqMobile 触发重渲染） */
  const table = `<div class="tbl-wrap"><table>
      <thead><tr><th>姓名 / 登录名</th><th>角色</th>${MODULES.map(m=>`<th>${m.n}</th>`).join('')}
      <th>状态</th><th>最后登录</th><th class="col-op" style="text-align:right">操作</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  const cards = `<div class="card-grid">${S.accounts.map((a,i)=>acctCardHTML(a,i,ro)).join('')
      || '<div class="empty"><p>暂无账号</p></div>'}</div>`;
  return `<div class="page-hd"><div><div class="page-title">账号管理</div>
      <div class="page-desc">维护本平台登录账号，并按模块分配「无权限 / 仅查看 / 可修改」三级权限</div></div>
    <div class="hd-actions"><button class="btn primary" data-act="acct-new" ${ro?'disabled':''}>+ 新增账号</button></div></div>
    ${ro?'<div class="ro-bar">当前账号对该模块只有查看权限。</div>':''}
    ${isMobile() ? cards : table}`;
}
/* 账号管理（竖屏卡片）：与 VPN 配置 / 目的地池同一套卡片语言 */
function acctCardHTML(a, i, ro){
  const on = (a.status===1||a.status==='on');
  const acts = [
    {act:'acct-edit', id:a.id, label: ro?'查看':'编辑'},
    {act:'acct-pw', id:a.id, label:'重置密码', disabled: !!ro},
    {act:'acct-del', id:a.id, label:'删除', danger:true, disabled: !!(ro||a.role==='admin')},
  ];
  const perms = MODULES.map(m=>`<span class="tag">${m.n} · ${a.role==='admin'?'可修改':(PERM_LABEL[a.perm[m.k]]||'无权限')}</span>`).join('');
  return `<div class="ucard row-click"${rowActsAttr(acts)} style="animation-delay:${i*35}ms">
    <div class="ucard-top">${accAvatar(a, 38)}
      <div style="min-width:0"><div class="ucard-name">${esc(a.name)}</div>
        <div class="ucard-ip">${esc(a.login)}</div></div>
      <div class="ft-meta" style="margin-left:auto">
        <span class="badge ${a.role==='admin'?'acc':''}">${esc(ROLES[a.role]||a.role)}</span>
        <span class="badge ${on?'ok':'danger'}"><i class="dot"></i>${on?'启用':'停用'}</span></div></div>
    <div class="ucard-body"><div class="ucard-tags">${perms}</div></div>
    <div class="ucard-ft"><span>最后登录：${a.last_login_at?ago(a.last_login_at):(a.lastLogin?ago(a.lastLogin):'—')}</span>
      <div class="row-acts">
        <button class="btn sm" data-act="acct-edit" data-id="${a.id}">${ro?'查看':'编辑'}</button>
        <button class="btn sm" data-act="acct-pw" data-id="${a.id}" ${ro?'disabled':''}>重置密码</button>
        <button class="btn sm danger" data-act="acct-del" data-id="${a.id}" ${ro||a.role==='admin'?'disabled':''}>删除</button>
      </div></div>
  </div>`;
}
function acctForm(id){
  const a = id ? acct(id) : { name:'', login:'', role:'custom', status:1,
    perm:{account:'none',dest:'none',vpn:'none',audit:'none'} };
  const ro = !canEdit('account'), isAdmin = a.role==='admin';
  const roleOpts = Object.entries(ROLES).filter(([k])=>k!=='admin'||isAdmin).map(([k,v])=>({v:k,t:v}));
  const stVal = String((a.status==='on'?1:a.status) ?? 1);
  return `<div class="grid2">
      <div class="field"><label>真实姓名</label><input name="name" value="${esc(a.name)}" ${ro?'disabled':''}></div>
      <div class="field"><label>登录账号</label><input name="login" value="${esc(a.login)}" ${ro?'disabled':''}></div></div>
    ${combo('c_role',{label:'角色',value:a.role,options:roleOpts,onPick:()=>{}})}
    ${combo('c_status',{label:'状态',value:stVal,searchable:false,
      options:[{v:'1',t:'启用'},{v:'0',t:'停用'}],onPick:()=>{}})}
    ${id ? '' : `<div class="field"><label>初始密码</label><input name="password" type="text" value="${randPwd()}" spellcheck="false">
      <div class="hint">已自动生成强随机口令，请复制后安全转交本人。服务端策略：≥6 位且含大小写字母与数字。</div></div>`}
    <div class="field"><label>模块权限</label>
      <table class="perm-table"><thead><tr><th>模块</th><th>权限级别</th></tr></thead><tbody>
      ${MODULES.map(m=>`<tr><td>${m.n}</td><td><div class="seg" data-seg="${m.k}">
        ${['none','r','rw'].map(v=>`<button type="button" data-v="${v}"
          class="${(a.perm[m.k]||'none')===v?'on':''}" ${ro||isAdmin?'disabled':''}>${PERM_LABEL[v]}</button>`).join('')}
      </div></td></tr>`).join('')}</tbody></table>
      <div class="hint">超级管理员默认拥有全部权限，不受此矩阵限制。</div></div>`;
}

/* ================= 目的地池 ================= */
function viewDest(){
  const ro = !canEdit('dest');
  let body;
  if(ui.destTab==='pool'){
    const q = ui.q.pool.trim().toLowerCase();
    const list = S.pools.filter(p=>!q || (p.name+p.ip+p.port+p.proto).toLowerCase().includes(q));
    body = `<div class="dest-toolbar">
        ${sfield('sf_pool', ui.q.pool, v=>{ ui.q.pool=v; renderPoolCards(); },'搜索名称 / IP / 端口')}
        <button class="btn primary" data-act="pool-new" ${ro?'disabled':''}>+ 添加</button>
        <button class="btn ${ui.batch?'danger':''}" data-act="pool-batch" ${ro?'disabled':''}>${ui.batch?'退出批量':'批量管理'}</button>
      </div>
      <div class="card-grid ${ui.batch?'batch-on':''}" id="poolGrid">${poolCards(list, ro)}</div>
      ${ui.batch?`<div class="batch-bar"><span>已选中 <b>${ui.picked.size}</b> 个</span>
        <button class="btn sm" data-act="pool-selall">全选</button>
        <button class="btn sm" data-act="pool-clrsel">清空</button>
        <button class="btn danger sm" data-act="pool-batch-del">删除所选</button>
        <button class="btn sm ghost" data-act="pool-batch-cancel">取消</button></div>`:''}`;
  }else{
    body = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:15px">
      ${S.packages.map((k,i)=>{ const items=k.poolIds.map(pool).filter(Boolean);
        return `<div class="panel row-click" style="animation-delay:${i*45}ms"${rowActsAttr([
            {act:'pkg-edit', id:k.id, label: ro?'查看内容':'管理内容'},
            {act:'pkg-del', id:k.id, label:'删除', danger:true, disabled: !!ro},
          ])}>
          <div class="panel-hd"><div><div class="panel-title">${esc(k.name)}</div>
            <div class="sub" style="font-size:11.5px;color:var(--dim)">${esc(k.descr||'无说明')}</div></div>
            <span class="badge acc">${items.length} 项</span></div>
          <div class="ucard-tags" style="min-height:40px;margin-bottom:14px">
            ${items.length ? items.slice(0,4).map(p=>`<span class="tag pool">${esc(p.name)}
              <span style="opacity:.6">${esc(p.ip)}:${esc(portText(p.port))}</span></span>`).join('')
              + (items.length>4?`<span class="tag more">+${items.length-4}</span>`:'')
              : '<span class="empty-mini">尚未添加 IP-端口</span>'}</div>
          <div style="display:flex;gap:8px" class="row-acts">
            <button class="btn sm" data-act="pkg-edit" data-id="${k.id}">${ro?'查看内容':'管理内容'}</button>
            <button class="btn sm danger" data-act="pkg-del" data-id="${k.id}" ${ro?'disabled':''}>删除</button></div>
        </div>`;}).join('') || '<div class="empty"><p>暂无目的地包</p></div>'}</div>`;
  }
  return `<div class="page-hd"><div><div class="page-title">目的地池</div>
      <div class="page-desc">先维护 IP-端口池，再组合成「目的地包」，授权时可直接按包分配</div></div>
    ${ui.destTab!=='pool'?`<div class="hd-actions"><button class="btn primary" data-act="pkg-new" ${ro?'disabled':''}>+ 新增目的地包</button></div>`:''}</div>
    ${ro?'<div class="ro-bar">当前账号对该模块只有查看权限。</div>':''}
    <div class="tabs"><div class="tabs-cursor"></div><div class="tab ${ui.destTab==='pool'?'on':''}" data-act="dtab" data-v="pool">IP-端口池</div>
      <div class="tab ${ui.destTab==='pkg'?'on':''}" data-act="dtab" data-v="pkg">目的地包</div></div>
    <div class="tab-pane">${body}</div>`;
}
/* IP-端口池：卡片式（与 VPN 配置页同一套卡片语言） */
function poolCardHTML(p, i, ro){
  const on = ui.picked.has(String(p.id)), ck = ui.batch;
  const acts = [
    {act:'pool-edit', id:p.id, label: ro?'查看':'编辑'},
    {act:'pool-del', id:p.id, label:'删除', danger:true, disabled: !!ro},
  ];
  /* 批量态：点整卡 = 勾选 / 取消；非批量态：点整卡弹操作选单（竖屏），右下按钮操作（横屏） */
  const tap = ck ? ` data-act="pool-pick" data-id="${p.id}"` : rowActsAttr(acts);
  return `<div class="ucard pool-card${on?' pick':''}${ck?'':' row-click'}" data-batchpick="${p.id}"${tap}
      style="animation-delay:${i*35}ms">
    <div class="cbox ucard-pick ${on?'on':''}" data-act="pool-pick" data-id="${p.id}">${on?ICON.check:''}</div>
    <div class="ucard-top"><div class="avatar" style="background:${colorOf(p.name)}">${esc(String(p.name||'').slice(0,1))}</div>
      <div style="min-width:0"><div class="ucard-name">${esc(p.name)}</div>
        <div class="ucard-ip">${esc(p.ip)}:${esc(portText(p.port))}</div></div></div>
    <div class="ucard-body"><div class="ucard-tags">
      <span class="tag pool">${esc(p.proto)}</span>
      <span class="tag">${esc(svcOf(p.port))}</span>
      <span class="tag">${esc(portText(p.port))}</span></div></div>
    <div class="ucard-ft"><span>${esc(p.descr||'无说明')}</span>
      <div class="row-acts">
        <button class="btn sm" data-act="pool-edit" data-id="${p.id}">${ro?'查看':'编辑'}</button>
        <button class="btn sm danger" data-act="pool-del" data-id="${p.id}" ${ro?'disabled':''}>删除</button>
      </div></div>
  </div>`;
}
function poolCards(list, ro){
  return list.length
    ? list.map((p,i)=>poolCardHTML(p,i,ro)).join('')
    : '<div class="empty"><p>没有匹配的条目</p></div>';
}
function renderPoolCards(){
  const q = ui.q.pool.trim().toLowerCase();
  const list = S.pools.filter(p=>!q || (p.name+p.ip+p.port+p.proto).toLowerCase().includes(q));
  const w = $('#poolGrid'); if(w) w.innerHTML = poolCards(list, !canEdit('dest'));
}
function poolForm(id){
  const p = id ? pool(id) : { name:'', ip:'', port:'', proto:'TCP', descr:'' };
  const ro = !canEdit('dest');
  return `<div class="field"><label>名称</label><input name="name" value="${esc(p.name)}" ${ro?'disabled':''} placeholder="如：数据库-MySQL"></div>
    <div class="grid2"><div class="field"><label>IP 地址</label><input name="ip" value="${esc(p.ip)}" ${ro?'disabled':''} placeholder="10.0.20.5"></div>
    <div class="field"><label>端口或区间，用逗号分隔</label><input name="port" value="${esc(p.port)}" ${ro?'disabled':''} placeholder="所有端口"></div></div>
    ${combo('c_proto',{label:'协议',value:p.proto,searchable:false,
      options:[{v:'TCP',t:'TCP'},{v:'UDP',t:'UDP'}],onPick:()=>{}})}
    <div class="field" style="margin-bottom:0"><label>说明</label>
      <input name="descr" value="${esc(p.descr||'')}" ${ro?'disabled':''}></div>`;
}
function pkgForm(id){
  const k = id ? pkg(id) : { name:'', descr:'', poolIds:[] };
  const ro = !canEdit('dest');
  return `<div class="grid2"><div class="field"><label>包名称</label>
      <input name="name" value="${esc(k.name)}" ${ro?'disabled':''}></div>
    <div class="field"><label>说明</label><input name="descr" value="${esc(k.descr||'')}" ${ro?'disabled':''}></div></div>
    <div class="field" style="margin-bottom:0"><label>包含的 IP-端口</label>
      ${sfield('sf_pkg', ui.q.pkg, v=>{ ui.q.pkg=v; const l=$('#pkgList'); if(l) l.innerHTML=pkgListHTML(); },'搜索名称 / IP / 端口')}
      <div class="chk-list" id="pkgList" style="margin-top:10px">${pkgListHTML()}</div></div>`;
}
function pkgListHTML(){
  const q = ui.q.pkg.trim().toLowerCase(), sel = (window.__pkgSel ||= []).map(String);
  const list = S.pools.filter(p=>!q || (p.name+p.ip+p.port+p.proto).toLowerCase().includes(q));
  return list.length ? list.map(p=>`<div class="chk-item" data-act="pkg-toggle" data-id="${p.id}">
      <div class="cbox ${sel.includes(String(p.id))?'on':''}">${sel.includes(String(p.id))?ICON.check:''}</div>
      <div class="ci-main"><div class="ci-t">${esc(p.name)}</div>
        <div class="ci-s">${esc(p.ip)}:${esc(p.port)} · ${esc(p.proto)} · ${esc(svc(p.port))}</div></div></div>`).join('')
    : '<div class="chk-empty">没有匹配的结果</div>';
}

/* 用户卡片（外层展示）：黑名单模式显示鎏金边框 + 模式徽标，卡片尺寸不变化 */
function ucardHTML(v, i){
  const tags=grantTags(v), n=grantCount(v), black = v.mode==='deny';
  return `<div class="ucard ${black?'black':''} ${ui.picked.has(String(v.id))?'pick':''}" data-act="vpn-open" data-id="${v.id}"
      data-batchpick="${v.id}" style="animation-delay:${i*40}ms">
    <div class="cbox ucard-pick ${ui.picked.has(String(v.id))?'on':''}" data-act="vpn-pick" data-id="${v.id}">${ui.picked.has(String(v.id))?ICON.check:''}</div>
    <div class="ucard-top"><div class="avatar" style="background:${colorOf(v.name)}">${esc(v.name.slice(0,1))}</div>
      <div style="min-width:0"><div class="ucard-name">${esc(v.name)}</div><div class="ucard-ip">${esc(v.ip)}</div></div></div>
    <div class="ucard-body"><div class="ucard-tags">
      ${tags.length ? tags.slice(0,3).map(t=>`<span class="tag ${t.cls}">${esc(t.t)}</span>`).join('')
        + (tags.length>3?`<span class="tag more">+${tags.length-3}</span>`:'')
        : '<span class="empty-mini">尚未授权任何目的地</span>'}</div></div>
    <div class="ucard-ft"><span>${black?`${n} 个禁止例外`:`${n} 个可访问目的地`}</span>
      <div class="ft-meta">
        ${black?`<span class="mode-badge">黑名单</span>`:''}
        <span class="badge ${(v.status===1||v.status==='on')?'ok':''}">${(v.status===1||v.status==='on')?'正常':'停用'}</span>
      </div></div>
  </div>`;
}

/* ================= VPN 配置 ================= */
function viewVpn(){
  const ro = !canEdit('vpn');
  const q = ui.q.vpn.trim().toLowerCase();
  const list = S.vpn.filter(v=>!q || (v.name+v.ip).toLowerCase().includes(q));
  const cards = list.map((v,i)=>ucardHTML(v,i)).join('');
  return `<div class="page-hd"><div><div class="page-title">VPN 配置</div>
      <div class="page-desc">按真实姓名分配 VPN 账号；点击卡片进入可视化授权页勾选可访问的目的地</div></div>
    <div class="hd-actions">
      <div style="width:216px">${sfield('sf_vpn', ui.q.vpn, v=>{ ui.q.vpn=v; renderVpnCards(); },'搜索姓名 / IP')}</div>
      <button class="btn ${ui.batch?'danger':''}" data-act="vpn-batch" ${ro?'disabled':''}>${ui.batch?'退出批量':'批量管理'}</button>
      <button class="btn primary" data-act="vpn-new" ${ro?'disabled':''}>+ 新增用户</button></div></div>
    ${ro?'<div class="ro-bar">当前账号对该模块只有查看权限。</div>':''}
    <div class="card-grid ${ui.batch?'batch-on':''}" id="vpnGrid">${cards || '<div class="empty"><p>没有匹配的用户</p></div>'}</div>
    ${ui.batch?`<div class="batch-bar"><span>已选中 <b>${ui.picked.size}</b> 个</span>
      <button class="btn sm" data-act="vpn-selall">全选</button>
      <button class="btn sm" data-act="vpn-clrsel">清空</button>
      <button class="btn danger sm" data-act="vpn-batch-del">删除所选</button>
      <button class="btn sm ghost" data-act="vpn-batch-cancel">取消</button></div>`:''}`;
}
function renderVpnCards(){
  const q = ui.q.vpn.trim().toLowerCase(), ro = !canEdit('vpn');
  const list = S.vpn.filter(v=>!q || (v.name+v.ip).toLowerCase().includes(q));
  const g = $('#vpnGrid'); if(!g) return;
  g.innerHTML = list.map((v,i)=>ucardHTML(v,i)).join('') || '<div class="empty"><p>没有匹配的用户</p></div>';
}
function vpnForm(){
  return `<div class="field"><label>真实姓名</label><input name="name" placeholder="如：陈晓明"></div>
    <div class="grid2"><div class="field"><label>VPN 内网 IP</label><input name="vpn_ip" placeholder="留空自动分配">
      <div class="hint">自动分配：10.100.0.x 取当前最大值 +1</div></div>
    <div class="field"><label>部门 / 备注</label><input name="note" placeholder="选填"></div></div>
    <div class="field" style="margin-bottom:0"><label>访问授权</label>
      <div class="hint" style="margin-top:0">创建后默认为<b>空权限</b>，需点击卡片授权后才能访问任何目的地。</div></div>`;
}
function openGrant(id){
  const v = vuser(id); if(!v) return;
  ui.editGrants = JSON.parse(JSON.stringify(v.grants)); ui.q.grant='';
  ui.editMode = v.mode==='deny' ? 'deny' : 'allow';
  const black = ui.editMode==='deny';
  $('#layer').innerHTML = `<div class="drawer-wrap" data-backdrop><div class="drawer ${black?'black':''}">
    <div class="drawer-hd"><div style="display:flex;align-items:center;gap:11px">
      <div class="avatar" style="background:${colorOf(v.name)}">${esc(v.name.slice(0,1))}</div>
      <div><div style="font-size:15px;font-weight:600">${esc(v.name)}</div>
        <div class="ucard-ip">${esc(v.ip)} · ${esc(v.note||'无备注')}</div></div></div>
      <button class="icon-btn" data-close>×</button></div>
    <div class="drawer-bd">
      <div class="mode-toggle ${black?'on':''}" data-act="mode-toggle">
        <div class="mt-left"><div class="mt-title"><span class="mode-badge">黑名单</span> 黑名单模式</div>
          <div class="mt-sub">开启后默认放行全部网段，勾选的目的地将被禁止访问</div></div>
        <span class="am-switch ${black?'on':''}"><span class="am-knob"></span></span>
      </div>
      <div class="blk-hint" id="blkHint" style="${black?'':'display:none'}">
        ⚠ 黑名单模式：该用户默认可访问<b>所有网段</b>，下方勾选的目的地将被<b>禁止访问</b>（其余全部放行）。</div>
      ${sfield('sf_grant','',q=>{ ui.q.grant=q; const l=$('#grantList'); if(l) l.innerHTML=grantListHTML(); },'搜索 IP-端口或目的地包')}
      <div id="grantList" style="margin-top:12px">${grantListHTML()}</div></div>
    <div class="drawer-ft"><div class="left">
      <button class="btn danger" data-act="vpn-del" data-id="${v.id}" ${!canEdit('vpn')?'disabled':''}>删除用户</button>
      <button class="btn danger" data-act="grant-clear" ${!canEdit('vpn')?'disabled':''}>清空授权</button>
      <button class="btn" data-act="vpn-conf" data-id="${v.id}">客户端配置</button></div>
      <div style="display:flex;gap:9px"><button class="btn" data-close>取消</button>
      <button class="btn primary" data-act="grant-save" data-id="${v.id}" ${!canEdit('vpn')?'disabled':''}>保存授权</button></div></div>
  </div></div>`;
  bindSF();
}
async function showVpnConf(id, note){
  let r;
  try{ r = await api('GET','vpn/'+id+'/conf'); }
  catch(e){ return toast(e.message,'err'); }
  const noteHTML = note ? `<div class="warn-box">${esc(note)}</div>` : '';
  modal({ title:`客户端配置 — ${r.name}`, wide:true,
    body:`${noteHTML}<div class="field"><label>${esc(r.name)} · ${esc(r.vpn_ip)}</label>
      <textarea id="wgConf" class="wg-conf" readonly rows="15">${esc(r.conf)}</textarea></div>
      <div class="hint">私钥明文仅在服务端解密后下发，不会再次以明文存储。请通过安全渠道交付给用户，本窗口关闭后需重新点击「客户端配置」查看。</div>`,
    extra:'<button class="btn" id="copyConf">复制</button>',
    okText:'下载 .conf',
    after: ()=>{ const b=document.getElementById('copyConf');
      if(b) b.onclick=()=>{ const t=document.getElementById('wgConf'); t.select();
        navigator.clipboard?.writeText(t.value); toast('已复制'); }; },
    onOk: ()=>{ const t=document.getElementById('wgConf'); if(!t) return;
      const a=document.createElement('a');
      a.href=URL.createObjectURL(new Blob([t.value],{type:'text/plain;charset=utf-8'}));
      a.download=`${r.name}-wg.conf`; a.click(); toast('已下载'); } });
}
function grantListHTML(){
  const q = ui.q.grant.trim().toLowerCase(), sel = ui.editGrants;
  const deny = ui.editMode==='deny';
  const has = (t,id) => sel.some(g=>g.t===t && String(g.id)===String(id));
  const suffix = deny ? ' · 勾选即禁止（默认全放行）' : '';
  const ps = S.pools.filter(p=>!q || (p.name+p.ip+p.port).toLowerCase().includes(q));
  const ks = S.packages.filter(k=>!q || (k.name+(k.descr||'')).toLowerCase().includes(q));
  const row = (t,id,title,sub) => `<div class="chk-item" data-act="grant-toggle" data-t="${t}" data-id="${id}">
    <div class="cbox ${has(t,id)?'on':''}">${has(t,id)?ICON.check:''}</div>
    <div class="ci-main"><div class="ci-t">${title}</div><div class="ci-s">${sub}</div></div></div>`;
  return `<div class="chk-group"><div class="chk-group-hd">
      <span class="chk-group-t">目的地包${suffix}</span><span class="chk-group-n">${ks.length} 个</span></div>
    <div class="chk-list">${ks.length ? ks.map(k=>row('pkg',k.id,esc(k.name),`${k.poolIds.length} 个 IP-端口`)).join('')
      : '<div class="chk-empty">没有匹配的目的地包</div>'}</div></div>
    <div class="chk-group"><div class="chk-group-hd">
      <span class="chk-group-t">IP-端口池${suffix}</span><span class="chk-group-n">${ps.length} 个</span></div>
    <div class="chk-list">${ps.length ? ps.map(p=>row('pool',p.id,esc(p.name),`${esc(p.ip)}:${esc(portText(p.port))} · ${esc(p.proto)}${/^\d+$/.test(String(p.port))?' · '+esc(svc(Number(p.port))):''}`)).join('')
      : '<div class="chk-empty">没有匹配的 IP-端口</div>'}</div></div>`;
}

/* ================= 访问追踪 ================= */
async function loadLogs(){
  try{
    const p = new URLSearchParams();
    Object.entries(ui.f).forEach(([k,v])=>{ if(v) p.set(k,v); });
    const r = await api('GET','logs?'+p.toString());
    S.logs = (r.rows||[]).map(x=>({...x, ts:new Date(String(x.ts).replace(' ','T'))}));
    S.stats = await api('GET','stats');
  }catch(e){ toast(e.message,'err'); }
  const t = $('#logTbl'); if(t) t.innerHTML = logTblHTML();
  const s = $('#statBox'); if(s) s.innerHTML = statHTML();
}
function statHTML(){
  const st = S.stats || {};
  return `<div class="stat"><div class="stat-label">今日访问</div><div class="stat-val">${st.today??'—'}</div>
      <div class="stat-sub">全部用户合计</div></div>
    <div class="stat"><div class="stat-label">近 7 日访问</div><div class="stat-val">${st.week??'—'}</div>
      <div class="stat-sub">活跃 ${st.active??'—'} 人</div></div>
    <div class="stat"><div class="stat-label">被拒绝</div><div class="stat-val" style="color:var(--danger)">${st.denied??'—'}</div>
      <div class="stat-sub">越权访问尝试</div></div>
    <div class="stat"><div class="stat-label">当前结果</div><div class="stat-val">${S.logs.length}</div>
      <div class="stat-sub">最多展示 200 条</div></div>`;
}
/* 管理员操作审计（竖屏卡片）：与其它页面同一套卡片语言 */
function auditCards(){
  return S.audits.length ? S.audits.map((a,i)=>`<div class="ucard" style="animation-delay:${i*20}ms">
    <div class="ucard-top"><div style="min-width:0">
        <div class="ucard-name">${esc(a.actor)}</div>
        <div class="ucard-ip">${fmt(a.ts)}</div></div>
      <span class="badge acc" style="margin-left:auto;flex:none">${esc(a.action)}</span></div>
    <div class="ucard-ft"><span>对象：${esc(a.target||'—')}</span>
      <span class="sub mono">${esc(a.ip||'—')}</span></div>
  </div>`).join('') : '<div class="empty"><p>暂无审计记录</p></div>';
}
function viewAudit(){
  if(ui.auditTab==='audit'){
    const rows = S.audits.map(a=>`<tr><td class="audit-line">${fmt(a.ts)}</td><td>${esc(a.actor)}</td>
      <td><span class="badge acc">${esc(a.action)}</span></td><td>${esc(a.target)}</td>
      <td class="sub mono">${esc(a.ip||'—')}</td></tr>`).join('');
    const table = `<div class="tbl-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>操作类型</th><th>对象</th><th>来源 IP</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5"><div class="empty"><p>暂无审计记录</p></div></td></tr>'}</tbody></table></div>`;
    return `<div class="page-hd"><div><div class="page-title">访问追踪</div>
      <div class="page-desc">管理员在本平台的操作留痕，满足安全审计的可追溯要求</div></div></div>
      <div class="tabs"><div class="tabs-cursor"></div><div class="tab" data-act="atab" data-v="access">用户访问记录</div>
        <div class="tab on" data-act="atab" data-v="audit">管理员操作审计</div></div>
      <div class="tab-pane">${isMobile() ? `<div class="card-grid">${auditCards()}</div>` : table}</div>`;
  }
  return `<div class="page-hd"><div><div class="page-title">访问追踪</div>
      <div class="page-desc">每一条新建连接：谁、在什么时候、访问了哪个 IP 的哪个端口、是否被放行</div></div>
    <div class="hd-actions"><button class="btn" data-act="csv">导出 CSV</button></div></div>
    <div class="tabs"><div class="tabs-cursor"></div><div class="tab on" data-act="atab" data-v="access">用户访问记录</div>
      <div class="tab" data-act="atab" data-v="audit">管理员操作审计</div></div>
    <div class="tab-pane">
    <div class="stats" id="statBox">${statHTML()}</div>
    <div class="filters">
      <div style="min-width:172px">${combo('c_fname',{label:'姓名',value:ui.f.name,ph:'全部用户',
        options:[{v:'',t:'全部用户'}].concat(S.vpn.map(v=>({v:v.name,t:v.name,s:v.ip}))),
        onPick:v=>{ ui.f.name=v; refresh(); loadLogs(); }})}</div>
      <div class="field" style="min-width:150px"><label>目标 IP</label>
        <input id="fDst" value="${esc(ui.f.dst)}" placeholder="如 10.0.20"></div>
      <div class="field" style="min-width:110px"><label>端口</label>
        <input id="fPort" value="${esc(ui.f.port)}" placeholder="如 3389"></div>
      <div style="min-width:136px">${combo('c_fact',{label:'结果',value:ui.f.act,ph:'全部',searchable:false,
        options:[{v:'',t:'全部'},{v:'ALLOW',t:'放行'},{v:'DENY',t:'拒绝'}],
        onPick:v=>{ ui.f.act=v; refresh(); loadLogs(); }})}</div>
      <div style="min-width:150px">${combo('c_fdays',{label:'时间范围',value:ui.f.days,ph:'全部',searchable:false,
        options:[{v:'',t:'全部'},{v:'1',t:'最近 1 天'},{v:'7',t:'最近 7 天'},{v:'30',t:'最近 30 天'}],
        onPick:v=>{ ui.f.days=v; refresh(); loadLogs(); }})}</div>
      <div class="field"><button class="btn" data-act="fclear">重置</button></div></div>
    <div class="tbl-wrap" id="logTbl">${logTblHTML()}</div>
    </div>`;
}
function logTblHTML(){
  const rows = S.logs.slice(0,200).map(l=>`<tr><td class="audit-line">${fmt(l.ts)}</td>
    <td>${esc(l.user_name||'—')}<div class="sub mono">${esc(l.src_ip)}</div></td>
    <td class="mono">${esc(l.dst_ip)}</td>
    <td class="mono">${esc(l.dst_port)}<div class="sub">${esc(svc(l.dst_port))}</div></td>
    <td><span class="badge">${esc(l.proto)}</span></td>
    <td><span class="badge ${l.action==='ALLOW'?'ok':'danger'}">${esc(l.action)}</span></td></tr>`).join('');
  return `<table><thead><tr><th>时间</th><th>姓名 / 来源 IP</th><th>目标 IP</th><th>端口</th><th>协议</th><th>结果</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6"><div class="empty"><p>没有符合条件的记录</p></div></td></tr>'}</tbody></table>`;
}
function bindLogFilters(){
  const b=(id,k)=>{ const el=$(id); if(!el||el._b) return; el._b=1;
    el.oninput=()=>{ ui.f[k]=el.value; clearTimeout(el._t); el._t=setTimeout(()=>loadLogs(),280); }; };
  b('#fDst','dst'); b('#fPort','port');
}

/* ---------------- 弹窗 ---------------- */
function modal(o){
  $('#layer').innerHTML = `<div class="modal-wrap" data-backdrop><div class="modal${o.wide?' wide':''}">
    <div class="modal-hd"><h3>${esc(o.title)}</h3><button class="icon-btn" data-close>×</button></div>
    <div class="modal-bd">${o.body}</div>
    <div class="modal-ft">${o.extra||''}<button class="btn" data-close>取消</button>
      <button class="btn primary" data-ok>${esc(o.okText||'保存')}</button></div></div></div>`;
  const ok = $('#layer [data-ok]');
  if(ok) ok.onclick = async ()=>{
    if(!o.onOk) return closeLayer();
    ok.disabled = true;
    try{ if(await o.onOk() !== false) closeLayer(); } finally { ok.disabled = false; }
  };
  bindSF(); if(o.after) o.after();
}
function confirmBox(title, msg, onYes, okText='确认删除'){
  modal({title, body:`<div style="font-size:13.5px;line-height:1.8">${msg}</div>`, okText, onOk:onYes});
  const ok = $('#layer [data-ok]'); if(ok) ok.className='btn danger';
}
/* 高危二次确认：必须手动输入「确认」才放行（用于黑名单模式提交等不可逆/大面积变更） */
function confirmDanger(title, msg, onYes){
  document.getElementById('cfmOverlay')?.remove();
  const ov = document.createElement('div');
  ov.id = 'cfmOverlay'; ov.className = 'modal-wrap confirm-overlay';
  ov.style.zIndex = '210';
  ov.innerHTML = `<div class="modal danger-modal">
    <div class="modal-hd"><h3>${esc(title)}</h3><button class="icon-btn" data-cfm-x>×</button></div>
    <div class="modal-bd"><div class="warn-box">${msg}</div>
      <div class="field" style="margin-top:14px"><label>输入「确认」以继续</label>
        <input id="cfmInput" class="cfm-input" placeholder="确认" autocomplete="off" spellcheck="false"></div></div>
    <div class="modal-ft"><button class="btn" data-cfm-cancel>取消</button>
      <button class="btn danger" id="cfmOk" disabled>确认执行</button></div></div>`;
  document.body.appendChild(ov);
  const inp = ov.querySelector('#cfmInput'), ok = ov.querySelector('#cfmOk');
  inp.oninput = ()=>{ ok.disabled = inp.value.trim() !== '确认'; };
  inp.focus();
  const close = ()=> ov.remove();
  ov.addEventListener('click', e=>{ if(e.target === ov) close(); });
  ov.querySelector('[data-cfm-x]').onclick = close;
  ov.querySelector('[data-cfm-cancel]').onclick = close;
  ok.onclick = async ()=>{
    if(inp.value.trim() !== '确认'){ toast('请输入「确认」','err'); return; }
    ok.disabled = true;
    try{ await onYes(); ov.remove(); }catch(e){ toast(e.message,'err'); ok.disabled = false; }
  };
}
function readForm(){ const o={}; $$('#layer [name]').forEach(e=>o[e.name]=e.value.trim()); return o; }
/* 密码输入框（带「显示/隐藏」眼睛按钮）。opts: {ac,ph,val,hint,last} */
function pwField(label, name, opts){
  opts = opts || {};
  const ac  = opts.ac  ? ` autocomplete="${opts.ac}"` : '';
  const ph  = opts.ph  ? ` placeholder="${opts.ph}"`   : '';
  const val = opts.val ? ` value="${opts.val}"`       : '';
  const hint= opts.hint? `<div class="hint">${opts.hint}</div>` : '';
  const lb  = opts.last ? ' style="margin-bottom:0"'  : '';
  return `<div class="field"${lb}><label>${label}</label>
    <div class="pw-wrap">
      <input name="${name}" type="password"${ac}${ph}${val} spellcheck="false">
      <button type="button" class="pw-eye" data-act="pw-toggle" tabindex="-1" title="显示密码" aria-label="显示密码">${ICON.eye}</button>
    </div>${hint}</div>`;
}
const segVal = k => { const b=$(`#layer .seg[data-seg="${k}"] .on`); return b?b.dataset.v:'none'; };
const comboVal = id => (COMBOS[id] ? COMBOS[id].value : null);
function bindSeg(){ $$('#layer .seg').forEach(s=>s.querySelectorAll('button').forEach(b=>{
  if(b.disabled) return;
  b.onclick=()=>{ s.querySelectorAll('button').forEach(x=>x.classList.remove('on')); b.classList.add('on'); }; })); }

/* ---------------- 事件 ---------------- */
const ACT = {
  nav: el=>{ const k=el.dataset.k, sel=el.dataset.sel||el.dataset.k;
    document.getElementById('avatarMenu')?.remove();
    if(ui.sel===sel && ui.route===k) return;
    ui.route=k; ui.sel=sel; ui.batch=false; ui.picked.clear(); lpSig=null; saveUi();
    [...document.querySelectorAll('.dock-item, .mbar-item')].forEach(i=>i.classList.toggle('sel', i.dataset.sel===sel));
    moveCursorTo(); moveMbarCursor();
    const name=currentPathName();
    const sp=$('.strip-path b'); if(sp) sp.textContent=name;
    const mt=$('.mtop-title'); if(mt) mt.textContent=name;
    refresh(); if(ui.route==='audit'){ bindLogFilters(); loadLogs(); } },
  'dock-toggle': ()=>{ ui.dockOpen=!ui.dockOpen; document.body.classList.toggle('dock-open', ui.dockOpen);
    requestAnimationFrame(moveCursorTo); },
  'avatar-toggle': el=> toggleAvatarMenu(el),
  'theme-toggle': ()=>{
    setTheme(THEME==='light' ? 'dark' : 'light');
    document.querySelectorAll('.am-switch[data-act="theme-toggle"]').forEach(sw=>{
      sw.classList.toggle('on', THEME==='light'); sw.setAttribute('aria-checked', String(THEME==='light')); });
    const lt = document.querySelector('.login-theme');
    if(lt){ lt.innerHTML = `${THEME==='light'?ICON.moon:ICON.sun}`; }
  },
  'avatar-edit': ()=>{
    let inp=document.getElementById('avatarFile');
    if(!inp){ inp=document.createElement('input'); inp.type='file'; inp.id='avatarFile';
      inp.accept='image/png,image/jpeg,image/webp'; inp.style.display='none'; document.body.appendChild(inp);
      inp.onchange=()=>{ const f=inp.files&&inp.files[0]; if(!f) return;
        if(f.size>3*1024*1024){ toast('原图不能超过 3MB（提交时会自动压缩尺寸）','err'); return; }
        const rd=new FileReader(); rd.onload=()=>openAvatarCrop(String(rd.result)); rd.readAsDataURL(f); }; }
    inp.click();
  },
  'reload': async ()=>{ document.getElementById('avatarMenu')?.remove();
    await loadState(); if(ui.route==='audit') loadLogs(); refresh(); toast('已刷新'); },
  'pw-toggle': el=>{
    const wrap = el.closest('.pw-wrap'); if(!wrap) return;
    const inp = wrap.querySelector('input'); if(!inp) return;
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    el.classList.toggle('on', show);
    el.innerHTML = show ? ICON.eyeOff : ICON.eye;
    el.title = show ? '隐藏密码' : '显示密码';
    el.setAttribute('aria-label', el.title);
  },
  'self-pw': ()=>{ document.getElementById('avatarMenu')?.remove();
    modal({title:'修改我的密码',
      body:`${pwField('原密码','old',{ac:'current-password'})}
        ${pwField('新密码','next',{ac:'new-password',hint:'服务端策略：≥6 位，且同时包含大小写字母与数字。'})}
        ${pwField('确认新密码','next2',{ac:'new-password',last:true})}`,
      okText:'修改',
      onOk: async ()=>{
        const g=readForm();
        if(!g.old || !g.next){ toast('请填写原密码与新密码','err'); return false; }
        if(g.next !== g.next2){ toast('两次输入的新密码不一致','err'); return false; }
        try{ await api('POST','auth/password',{old:g.old,next:g.next}); toast('密码已修改'); }
        catch(e){ toast(e.message,'err'); return false; }
      }}); },
  'logout': async ()=>{ document.getElementById('avatarMenu')?.remove();
    try{ await api('POST','auth/logout',{}); }catch{}
    me=null; render(); },

  'dtab': el=>{ rememberTabCursor(); ui.destTab=el.dataset.v; saveUi(); refresh(); },
  'atab': el=>{ rememberTabCursor(); ui.auditTab=el.dataset.v; saveUi(); refresh();
    if(ui.auditTab==='access'){ bindLogFilters(); loadLogs(); }
    else loadAudits().then(()=>refresh()); },
  'fclear': ()=>{ ui.f={name:'',dst:'',port:'',act:'',days:''}; refresh(); loadLogs(); },
  'csv': ()=>{
    const csv = ['时间,姓名,来源IP,目标IP,端口,协议,结果'].concat(S.logs.map(l=>
      [fmt(l.ts), l.user_name, l.src_ip, l.dst_ip, l.dst_port, l.proto, l.action].join(','))).join('\n');
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));
    a.download=`vpn-access-${Date.now()}.csv`; a.click(); toast(`已导出 ${S.logs.length} 条`);
  },
  'sclear': el=>{ const i=document.getElementById(el.dataset.t); if(!i) return;
    i.value=''; i.closest('.sfield')?.classList.remove('has'); i.dispatchEvent(new Event('input')); i.focus(); },
  'combo-toggle': el=>{ const box=el.closest('.combo');
    if(box.classList.contains('open')){ box.classList.remove('open'); const p=box.querySelector('.combo-pop'); if(p) p.remove(); return; }
    closeCombos(); box.classList.add('open');
    box.insertAdjacentHTML('beforeend', comboPop(box.dataset.combo));
    bindSF(); const inp=box.querySelector('.combo-search input'); if(inp) setTimeout(()=>inp.focus(),30); },
  'combo-pick': el=>{ const box=el.closest('.combo'), id=box.dataset.combo, c=COMBOS[id];
    c.value=el.dataset.v;
    const cur=c.options.find(o=>String(o.v)===String(c.value));
    const val=box.querySelector('.combo-val');
    val.textContent=cur?cur.t:(c.ph||'请选择'); val.classList.toggle('ph',!cur);
    closeCombos(); if(c.onPick) c.onPick(c.value); },

  /* 账号 */
  'acct-new': ()=> modal({title:'新增管理员账号', wide:true, body:acctForm(null), after:bindSeg, onOk: async ()=>{
      const g=readForm(); if(!g.name||!g.login){ toast('姓名与登录账号必填','err'); return false; }
      const perm={}; MODULES.forEach(m=>perm[m.k]=segVal(m.k));
      await api('POST','accounts',{...g, ...flatPerm(perm), role:comboVal('c_role')||'custom',
          status:Number(comboVal('c_status')??1)});
      await loadState();
      refresh(); toast('账号已创建'); }}),
  'acct-edit': el=>{ const a=acct(el.dataset.id);
    modal({title:'编辑账号权限', wide:true, body:acctForm(a.id), after:bindSeg, onOk: async ()=>{
      if(!canEdit('account')) return;
      const g=readForm(); const perm={}; MODULES.forEach(m=>perm[m.k]=segVal(m.k));
      await api('PUT','accounts/'+a.id,{...g, ...flatPerm(perm), role:comboVal('c_role')||a.role,
          status:Number(comboVal('c_status')??1)});
      await loadState();
      refresh(); toast('已保存'); }}); },
  'acct-pw': el=>{ const a=acct(el.dataset.id);
    modal({title:`重置密码 — ${a.name}`,
      body:`<div class="field"><label>新密码</label><input name="password" type="text" value="${randPwd()}" spellcheck="false"></div>
        <div class="hint">已自动生成强随机口令，请复制后安全转交本人；重置后强制下次登录修改。</div>`,
      okText:'重置', onOk: async ()=>{
        await api('POST',`accounts/${a.id}/password`,{password:readForm().password});
        toast('密码已重置'); }}); },
  'acct-del': el=>{ const a=acct(el.dataset.id);
    if(a.role==='admin') return toast('超级管理员不可删除','err');
    confirmBox('删除账号',`确定删除 <b>${esc(a.name)}</b>（${esc(a.login)}）吗？该操作不可撤销。`, async ()=>{
      await api('DELETE','accounts/'+a.id); await loadState();
      refresh(); toast('已删除'); }); },
  /* 目的地 */
  'pool-new': ()=> modal({title:'新增 IP-端口', body:poolForm(null), onOk: async ()=>{
      const g=readForm(); if(!g.name||!g.ip){ toast('名称与 IP 必填（端口留空=所有端口）','err'); return false; }
      await api('POST','pools',{...g,proto:comboVal('c_proto')||'TCP'}); await loadState();
      refresh(); toast('已添加'); }}),
  'pool-edit': el=>{ const p=pool(el.dataset.id);
    modal({title:'编辑 IP-端口', body:poolForm(p.id), onOk: async ()=>{
      if(!canEdit('dest')) return;
      const g=readForm();
      await api('PUT','pools/'+p.id,{...g,proto:comboVal('c_proto')||p.proto}); await loadState();
      refresh(); toast('已保存'); }}); },
  'pool-del': el=>{ const p=pool(el.dataset.id);
    confirmBox('删除 IP-端口',`确定删除 <b>${esc(p.name)}</b>（${esc(p.ip)}:${esc(portText(p.port))}）吗？引用它的包会同步移除。`, async ()=>{
      await api('DELETE','pools/'+p.id); await loadState();
      refresh(); toast('已删除'); }); },
  'pool-batch': ()=>{ if(!canEdit('dest')) return; lpSig=null; ui.batch=!ui.batch; ui.picked.clear(); refresh(); },
  'pool-pick': el=>{ const id=String(el.dataset.id); ui.picked.has(id)?ui.picked.delete(id):ui.picked.add(id); refresh(); },
  'pool-selall': ()=>{ const q=ui.q.pool.trim().toLowerCase();
    S.pools.filter(p=>!q||(p.name+p.ip+p.port+p.proto).toLowerCase().includes(q)).forEach(p=>ui.picked.add(String(p.id))); refresh(); },
  'pool-clrsel': ()=>{ ui.picked.clear(); refresh(); },
  'pool-batch-cancel': ()=>{ ui.batch=false; ui.picked.clear(); refresh(); },
  'pool-batch-del': ()=>{ if(!ui.picked.size) return toast('请先勾选要删除的条目','warn');
    const ids=[...ui.picked];
    confirmBox('批量删除目的地',`确定删除选中的 <b>${ids.length}</b> 个 IP-端口吗？引用它们的目的地包会同步移除。`, async ()=>{
      for(const id of ids){ try{ await api('DELETE','pools/'+id); }catch(e){} } await loadState();
      ui.picked.clear(); ui.batch=false; refresh(); toast(`已删除 ${ids.length} 个目的地`); }); },
  'pkg-new': ()=>{ window.__pkgSel=[]; ui.q.pkg='';
    modal({title:'新增目的地包', wide:true, body:pkgForm(null), onOk: async ()=>{
      const g=readForm(); if(!g.name){ toast('包名称必填','err'); return false; }
      await api('POST','packages',{...g,poolIds:window.__pkgSel}); await loadState();
      refresh(); toast('已创建'); }}); },
  'pkg-edit': el=>{ const k=pkg(el.dataset.id); window.__pkgSel=[...k.poolIds]; ui.q.pkg='';
    modal({title:`管理目的地包 — ${k.name}`, wide:true, body:pkgForm(k.id), onOk: async ()=>{
      if(!canEdit('dest')) return;
      const g=readForm();
      await api('PUT','packages/'+k.id,{...g,poolIds:window.__pkgSel}); await loadState();
      refresh(); toast('已保存'); }}); },
  'pkg-toggle': el=>{ if(!canEdit('dest')) return;
    const id=String(el.dataset.id), sel=(window.__pkgSel||=[]).map(String);
    const i=sel.indexOf(id); i>=0 ? sel.splice(i,1) : sel.push(id);
    window.__pkgSel=sel; const l=$('#pkgList'); if(l) l.innerHTML=pkgListHTML(); },
  'pkg-del': el=>{ const k=pkg(el.dataset.id);
    confirmBox('删除目的地包',`确定删除 <b>${esc(k.name)}</b> 吗？已授权该包的用户会同步失去权限。`, async ()=>{
      await api('DELETE','packages/'+k.id); await loadState();
      refresh(); toast('已删除'); }); },

  /* VPN */
  'vpn-new': ()=> modal({title:'新增 VPN 用户', body:vpnForm(), onOk: async ()=>{
      const g=readForm(); if(!g.name){ toast('请输入真实姓名','err'); return false; }
      const r=await api('POST','vpn',g); await loadState(); toast(`已创建 ${r.vpn_ip}，默认空权限`,'warn');
      if(r && r.id) setTimeout(()=>showVpnConf(r.id), 60);
      refresh(); }}),
  'vpn-del': el=>{ const v=vuser(el.dataset.id);
    confirmBox('删除 VPN 用户',`确定删除 <b>${esc(v.name)}</b>（${esc(v.ip)}）吗？历史访问记录会保留。`, async ()=>{
      await api('DELETE','vpn/'+v.id); await loadState();
      refresh(); toast('已删除'); }); },
  'vpn-open': el=>{ if(ui.batch) return ACT['vpn-pick'](el); openGrant(el.dataset.id); },
  'vpn-conf': el=> showVpnConf(el.dataset.id),
  'vpn-pick': el=>{ const id=String(el.dataset.id); ui.picked.has(id)?ui.picked.delete(id):ui.picked.add(id); refresh(); },
  'vpn-batch': ()=>{ lpSig=null; ui.batch=!ui.batch; ui.picked.clear(); refresh(); },
  'vpn-batch-cancel': ()=>{ ui.batch=false; ui.picked.clear(); refresh(); },
  'vpn-selall': ()=>{ S.vpn.forEach(v=>ui.picked.add(String(v.id))); refresh(); },
  'vpn-clrsel': ()=>{ ui.picked.clear(); refresh(); },
  'vpn-batch-del': ()=>{ if(!ui.picked.size) return toast('请先勾选用户','warn');
    confirmBox('批量删除',`确定删除已选中的 <b>${ui.picked.size}</b> 个用户吗？不可撤销。`, async ()=>{
      const ids=[...ui.picked];
      for(const id of ids) await api('DELETE','vpn/'+id); await loadState();
      ui.picked.clear(); ui.batch=false; refresh(); toast(`已删除 ${ids.length} 个用户`); }); },
  'grant-toggle': el=>{ const {t,id}=el.dataset;
    const i=ui.editGrants.findIndex(g=>g.t===t && String(g.id)===String(id));
    i>=0 ? ui.editGrants.splice(i,1) : ui.editGrants.push({t,id});
    const l=$('#grantList'); if(l) l.innerHTML=grantListHTML(); },
  'grant-clear': ()=>{ ui.editGrants=[]; const l=$('#grantList'); if(l) l.innerHTML=grantListHTML(); },
  /* 抽屉内「黑名单模式」开关：仅切换 ui.editMode 并就地刷新，不重置已勾选的目的地 */
  'mode-toggle': ()=>{
    ui.editMode = ui.editMode==='deny' ? 'allow' : 'deny';
    const black = ui.editMode==='deny';
    const el = document.querySelector('.mode-toggle');
    if(el){ el.classList.toggle('on', black);
      const sw = el.querySelector('.am-switch'); if(sw) sw.classList.toggle('on', black); }
    const hint = document.getElementById('blkHint'); if(hint) hint.style.display = black ? '' : 'none';
    const l = document.getElementById('grantList'); if(l) l.innerHTML = grantListHTML();
    const dr = document.querySelector('.drawer'); if(dr) dr.classList.toggle('black', black);
  },
  'grant-save': el=>{ const v=vuser(el.dataset.id);
    const before = { mode: v.mode, sig: grantSig(v.grants) };
    const save = async ()=>{
      await api('PUT',`vpn/${v.id}/grants`,{grants:ui.editGrants, mode:ui.editMode});
      await loadState(); closeLayer(); refresh();
      const after = vuser(v.id);
      const changed = before.mode !== after.mode || before.sig !== grantSig(after.grants);
      if(changed){
        // 授权模式或目的地变化会导致客户端 AllowedIPs 变化，弹出配置页提示重新下载（类比新增用户）
        showVpnConf(v.id, '授权模式或目的地已变更，客户端 AllowedIPs 随之变化。请重新下载上面的配置并导入客户端（旧配置不会自动更新）。');
      } else {
        toast(ui.editMode==='deny'
          ? `已启用黑名单模式：${v.name} 默认放行全部网段，${grantCount(after)} 个目的地被禁止`
          : `已保存，${v.name} 可访问 ${grantCount(after)} 个目的地`);
      }
    };
    if(ui.editMode==='deny'){
      confirmDanger('确认提交黑名单模式？',
        `即将把 <b>${esc(v.name)}</b> 设为<b>黑名单模式</b>：该用户默认<b>放行全部网段</b>，仅勾选的 ${ui.editGrants.length} 个目的地会被<b>禁止访问</b>。此变更会立即下发到网关，请确认无误。`,
        save);
    } else {
      save().catch(e=>toast(e.message,'err'));
    }
  },
};

/* ---------------- 全局委托 + 水波纹 ---------------- */
function ripple(host, e){
  const r=document.createElement('span'); r.className='ripple';
  const rc=host.getBoundingClientRect(), d=Math.max(rc.width,rc.height);
  r.style.width=r.style.height=d+'px';
  r.style.left=(e.clientX-rc.left-d/2)+'px'; r.style.top=(e.clientY-rc.top-d/2)+'px';
  host.appendChild(r); setTimeout(()=>r.remove(),640);
}
/* 长按条目：进入「批量管理」并勾选被长按的条目（等同于先点「批量管理」按钮、再点选该条）。
   ⚠️ 宿主自身可能带 data-act（VPN 卡片是 data-act="vpn-open"），所以只排除「内层的
   按钮 / 输入 / 勾选框 / 搜索框」这些真正的交互控件，绝不能按 [data-act] 一概排除
   —— 否则卡片长按会被自己的 data-act 拦掉（这正是此前 VPN 卡片长按失效的原因）。
   长按后吞掉尾随的 click —— 否则进入批量态后这次点击会变成一次「点选切换」把刚勾的取消。 */
let lpTimer=null, lpStart=null, lpFired=false, lpEl=null, lpGlow=null, lpSig=null;
/* 勾选集合快照：用于判断「长按进入批量后是否又改动过勾选」——没改动时点空白可快速退出 */
const pickSig = () => [...ui.picked].sort().join(',');
function lpReset(fired){
  if(lpTimer){ clearTimeout(lpTimer); lpTimer=null; }
  if(lpEl){ lpEl.classList.remove('lp-hold'); lpEl=null; }
  if(lpGlow){
    const g=lpGlow; lpGlow=null;
    if(fired){ g.classList.add('fire'); setTimeout(()=>g.remove(),520); }   // 触发：光环爆开
    else     { g.classList.add('out');  setTimeout(()=>g.remove(),200); }   // 取消：淡出
  }
  lpStart=null;
}
document.addEventListener('pointerdown', e=>{
  const el = e.target.closest('[data-batchpick]'); if(!el) return;
  if(e.target.closest('button,a,input,select,textarea,.cbox,.sfield')) return;   // 内层交互控件不算长按
  lpStart={x:e.clientX,y:e.clientY}; lpEl=el;
  el.classList.add('lp-hold');
  /* 反馈光环用 fixed 定位挂在 body 上：卡片与表格行都能用，不受 <tr> 无法定位的限制 */
  lpGlow=document.createElement('div'); lpGlow.className='lp-glow';
  lpGlow.style.left=e.clientX+'px'; lpGlow.style.top=e.clientY+'px';
  document.body.appendChild(lpGlow);
  lpTimer=setTimeout(()=>{
    lpTimer=null; lpFired=true; setTimeout(()=>{ lpFired=false; }, 700);   // 兜底复位
    lpReset(true);
    try{ navigator.vibrate && navigator.vibrate(18); }catch{}
    if(!ui.batch){ ui.batch=true; ui.picked.clear(); }
    ui.picked.add(String(el.dataset.batchpick));
    lpSig=pickSig();                       // 记住初始状态（仅勾选了被长按的这一条）
    refresh();
    toast('已进入批量管理，点空白处可直接退出');
  }, 500);
});
document.addEventListener('pointerup', ()=>lpReset(false));
document.addEventListener('pointercancel', ()=>lpReset(false));
document.addEventListener('pointermove', e=>{
  if(lpTimer && lpStart && (Math.abs(e.clientX-lpStart.x)>8 || Math.abs(e.clientY-lpStart.y)>8)) lpReset(false);
});
document.addEventListener('click', e=>{
  if(lpFired){ lpFired=false; e.stopPropagation(); e.preventDefault(); return; }   // 长按已处理，吞掉尾随 click
  if(e.target.closest('[data-close]')) return closeLayer();
  if(e.target.matches('[data-backdrop]')){
    if(isMobile() && layerHasUnsavedInput()) return;   // 移动端：二级菜单内有未保存输入时不关闭
    return closeLayer();
  }
  if(!e.target.closest('.combo')) closeCombos();
  /* 长按进入批量后若未再改动勾选（仍只有被长按那一条），点击任意「非条目区域」即快速退出批量管理 */
  if(lpSig!==null && ui.batch && pickSig()===lpSig &&
     !e.target.closest('[data-batchpick], .cbox, .batch-bar, .dest-toolbar, .hd-actions, .sfield, input, #layer, .avatar-menu, .pop-menu, [data-act]')){
    lpSig=null; ui.batch=false; ui.picked.clear(); refresh();
    return;
  }
  /* 竖屏：点击条目任意非交互区域，即在「点击位置」弹出操作选单（横屏保留操作列按钮，不触发） */
  const rh = e.target.closest('[data-rowacts]');
  if(rh && isMobile() && !e.target.closest('button,a,input,select,textarea,.cbox,.sfield,[data-act]')){
    try{ openActionMenu(rh, JSON.parse(rh.dataset.rowacts||'[]'), {x:e.clientX, y:e.clientY}); }catch{}
    return;
  }
  const t=e.target.closest('[data-act]'); if(!t) return;
  const fn=ACT[t.dataset.act];
  if(fn){
    const host=t.closest('.btn,.nav-item,.tab,.icon-btn,.dock-expand,.dock-item,.dock-idwrap,.dock-avatar,.mbar-item,.profile-avatar');
    if(host && !host.disabled) ripple(host, e);
    e.stopPropagation(); fn(t,e);
  }
});
document.addEventListener('keydown', e=>{ if(e.key==='Escape'){ closeCombos(); closeLayer(); } });

/* ---------------- 启动 ---------------- */
(async ()=>{
  try{
    /* 首次部署检测：admin 口令尚未设置时直接进入初始化页，不显示登录页 */
    const st = await api('GET','auth/setup-status'); needSetup = !!(st && st.needSetup);
    if(!needSetup){
      /* auth/me 在未登录时返回 401（正常「尚未登录」），静默忽略，仅当连接真正失败才报错 */
      try{
        const me0 = await api('GET','auth/me');
        if(me0 && me0.id){ me=me0; await loadState(); }
      }catch(e){ if(e.message!=='未登录') throw e; }
    }
  }catch(e){ appErr = e.message || '无法连接后端服务，请确认 server 已启动并配置 MySQL'; }
  const b=$('#boot'); if(b){ b.style.opacity='0'; setTimeout(()=>b.remove(),300); }
  setTheme(THEME);
  $('#app').hidden=false;
  if(me){
    const saved = loadUi();
    const okRoute = k => k==='settings' || !!MODULES.find(m=>m.k===k && canView(m.k));
    ui.route = okRoute(saved.route) ? saved.route : (MODULES.find(m=>canView(m.k))||MODULES[0]).k;
    ui.sel   = (saved.sel==='gear') ? 'gear' : ui.route;
    if(saved.destTab==='pool'||saved.destTab==='pkg') ui.destTab = saved.destTab;
    if(saved.auditTab==='access'||saved.auditTab==='audit') ui.auditTab = saved.auditTab;
  }
  render();
})();
