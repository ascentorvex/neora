/* Neora - main app: demo chat, workspace, model picker, voice input, menu, entrance animation */
(function(){
var $=function(s,c){return(c||document).querySelector(s)},$$=function(s,c){return Array.from((c||document).querySelectorAll(s))},D=document.documentElement;
var E1='cubic-bezier(0.16,1,0.3,1)',E2='cubic-bezier(0.22,1,0.36,1)',M=innerWidth<=680?.7:1,sleep=function(t){return new Promise(function(r){setTimeout(r,t)})};
var msgs=$('#msgs'),ta=$('#q'),inp=$('#q2'),live=$('#live'),busy=0,deep=0,s2d=0;

/* ---------- chat ---------- */
var AU='<span class="av u"><svg viewBox="0 0 24 24" width="60%" fill="none" stroke="#f2f2f2" stroke-width="1.7"><circle cx="12" cy="8.5" r="3.5"/><path d="M5 20c.8-4 3.6-5.5 7-5.5s6.2 1.5 7 5.5"/></svg></span>',AA='<span class="av a"></span>';
function tool(b,o){var NS=window.NEORA_STATUS,t=function(k){return NS?NS.t(o.l,k):k},d=document.createElement('div');if(o.h){d.className='tlh';d.textContent=t('tlh');b.append(d);return}
 if(o.k=='insp'){var v=o.v||{},n=v.n||{},ic={unsafe:'\uD83D\uDD34',suspicious:'\uD83D\uDFE1',clean:'\uD83D\uDFE2',incomplete:'\u26AA',static:'\uD83D\uDD35',partial:'\uD83D\uDFE3'},c=document.createElement('div');c.className='vd';c.setAttribute('data-l',/^(unsafe|suspicious|clean|incomplete|static|partial)$/.test(v.level)?v.level:'incomplete');var h=document.createElement('div');h.className='vh';h.textContent=(ic[v.level]||'')+' '+String(v.label||'').slice(0,90)+(typeof v.score=='number'?' \u00B7 '+v.score+'/100':'');var s=document.createElement('div');s.className='vs';s.textContent=String(v.target||'').slice(0,80)+' ('+String(v.kind||'').slice(0,8)+') \u00B7 '+t('crit')+' '+(n.c|0)+' \u00B7 '+t('high')+' '+(n.h|0)+' \u00B7 '+t('med')+' '+(n.m|0)+' \u00B7 '+t('low')+' '+(n.l|0);var r=document.createElement('div');r.className='vr';r.textContent=(v.ok?'\u2713 ':'\u26A0 ')+(v.ok?t('ok'):t('bad'))+' \u00B7 '+t('tail')+' \u00B7 '+Math.round((v.ms|0)/1000)+' s';c.append(h,s,r);b.append(c);return}
 if(o.dl){var bt=document.createElement('button');bt.type='button';bt.className='dl';bt.textContent='\u2B07 '+t('dl')+' \u00B7 '+o.dl.n;bt.onclick=function(){var u=URL.createObjectURL(new Blob([o.dl.c],{type:'text/markdown;charset=utf-8'})),l=document.createElement('a');l.href=u;l.download=o.dl.n;document.body.append(l);l.click();l.remove();setTimeout(function(){URL.revokeObjectURL(u)},4000)};b.append(bt);return}
 d=document.createElement('details');d.className='tool';d.open=true;var s=document.createElement('summary'),k=document.createElement('span');k.className='tk';k.textContent=({search:1,read:1,cmd:1}[o.k]?t(o.k):t('tool'));s.append(k,document.createTextNode(' '+(o.k=='cmd'?'$ ':'')+String(o.t||'').slice(0,160)));d.append(s);
 var sc=document.createElement('div');sc.className='sec';var r=o.r;sc.textContent=o.k=='cmd'?(r?'\uD83D\uDEE1 '+(r.p=='deny'?t('blocked'):t('sbx'))+' \u00B7 '+t('nonet')+' \u00B7 '+t('ro')+' \u00B7 128 MB \u00B7 '+r.ms+' ms \u00B7 '+t('cleanup')+' '+r.c+' \u00B7 '+t('receipt')+' '+r.h+(r.s?' ('+t('signed')+')':''):'\uD83D\uDEE1 '+t('sbx')+' \u00B7 '+t('nonet')+' \u00B7 '+t('ro')):'\uD83D\uDEE1 '+t('fetcher');d.append(sc);
 if(o.o){var p=document.createElement('pre');p.textContent=String(o.o).slice(0,1500);d.append(p)}b.append(d)}
function line(b,l){var d=document.createElement('div'),c='p';
 if(l.slice(0,2)=='^ '){try{tool(b,JSON.parse(l.slice(2)))}catch(e){}return}
 if(l.slice(0,3)=='## '){c='h';l=l.slice(3)}else if(l[0]=='•')c='li';else if(l.slice(0,2)=='~ '){c='note';l=l.slice(2)}
 else if(l.slice(0,2)=='% '||l.slice(0,3)=='%s '){var smp=l[1]=='s',n=Math.max(0,Math.min(100,+l.slice(smp?3:2)||0));d.className='cl';d.textContent=(smp?'Sample confidence: ':'Confidence: ')+n+'%';b.append(d);var g=document.createElement('div');g.className='cf';var i=document.createElement('i');i.style.width=n+'%';g.append(i);b.append(g);return}
 d.className=c;d.textContent=l;b.append(d)}
function add(role,lines,enter,box){box=box||msgs;var m=document.createElement('div'),b=document.createElement('div');m.className='m '+role;b.className='b';if(enter)m.setAttribute('data-enter','');
 (Array.isArray(lines)?lines:[lines]).forEach(function(l){var p=role=='u'?parseAtt(l):{t:l,f:[]};if(p.f.length){var r=document.createElement('div');r.className='att-row';p.f.forEach(function(n){r.append(attCard(n))});b.append(r)}if(p.t.trim()||!p.f.length)line(b,p.t)});
 if(role=='a')m.innerHTML=AA;m.append(b);if(role=='u')m.insertAdjacentHTML('beforeend',AU);box.append(m);var sc=box==msgs?msgs:wb;sc.scrollTop=sc.scrollHeight;if(box!=msgs)requestAnimationFrame(fit);return b}
add('u','Should we expand into the European market next quarter?',1);
add('a',['Let’s evaluate this across four dimensions:','• Market demand & competition','• Regulatory complexity','• Operational cost impact','• Long-term strategic value','Would you like to prioritize speed or profitability?'],1);
add('u','Analyze the Q3 sales data. Why did revenue drop in August?',1);
add('a',['## Example output','August revenue fell, and the dip lines up with fewer enterprise renewals.','• Hypothesis: renewals slipped to later months','• Next step: split the drop by contract size'],1);
add('u','Analyze our churn rate for February and draft a re-engagement email for inactive users',1);
add('a',['Here’s how I’d break it down:','• Define “inactive”: no login in 30 days','• Compare February churn with the 3-month average','• Draft a short email: one reason to return, one clear action','~ Example conversation for illustration.'],1);

msgs.scrollTop=0;

var T=[
['Let’s work through this in four steps:','• Pin down the metric and the time window','• Segment the change: who, where, which product','• Test the likeliest cause against the data','• Turn the finding into one concrete action','Want a hypothesis list or a full write-up first?'],
['Here’s how I’d structure it:','• Audience: who reads it and what they already know','• Hook: the one reason they should care','• Body: two or three proof points, in order','• Ask: one clear next step','Should I draft it in a direct or a warm tone?'],
['Let’s evaluate this across four dimensions:','• Upside and strategic value','• Cost, effort and timing','• Risks, and what would change your mind','• Reversibility if it goes wrong','Would you like to prioritize speed or confidence?'],
['Let’s break this down into four parts:','• The goal: what “done” looks like','• The constraints: what can’t change','• The options: two or three credible paths','• The first test: the cheapest way to learn more','Which part feels least clear right now?']];
function plan(q){q=parseAtt(q).t.trim()||q;var s=q.length>64?q.slice(0,61)+'…':q,k=/data|revenue|sales|churn|metric|analy|report|kpi/i.test(q)?0:/email|draft|write|post|message|letter|pitch/i.test(q)?1:/should|decide|whether|choose| vs |\bor\b/i.test(q)?2:3,t=T[k];
 return['## Structured brief','Working on: “'+s+'”',t[0]].concat(t.slice(1,5),deep?['• Deep check: stress-test the leading option against its weakest assumption']:[],[t[5],'%s '+(52+q.length*7%41),'~ Prototype preview: sample output, no live model connected yet.'])}
/* ---------- workspace (expands from the composer) ---------- */
var ws=$('#ws'),wb=$('#wb'),wm=$('#wm'),wi=$('#wi'),hi=$('#hi'),rcEl=$('#rc'),cur,src,ft=ta,K='neora.chats',reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
function stg(k){return k==K?sessionStorage:localStorage}
function lsGet(k){try{return stg(k).getItem(k)}catch(e){return null}}
function lsSet(k,v){try{stg(k).setItem(k,v)}catch(e){}}
function load(){try{return JSON.parse(lsGet(K)||'[]')}catch(e){return[]}}
function setDeep(v){deep=+!!v;$('#deep').classList.toggle('on',!!deep);$('#deep').setAttribute('aria-pressed',!!deep);lab();mdSync();lsSet('neora.deep',deep)}
function show(){hi.style.display=cur.m.length?'none':''}
function drawer(o){if(o)mm(0);ws.classList.toggle('sb',!!o)}
function recent(){var L=load();rcEl.textContent='';L.forEach(function(c){var b=document.createElement('button');b.textContent=c.t||'Untitled chat';b.onclick=function(){cur=c;wm.textContent='';c.m.forEach(function(m){add(m[0],m[1],0,wm)});show();drawer(0);wb.scrollTop=wb.scrollHeight};rcEl.append(b)});if(!L.length)rcEl.textContent='No recent chats yet.'}
function save(){var L=load().filter(function(c){return c.id!=cur.id});L.unshift(cur);lsSet(K,JSON.stringify(L.slice(0,20)));recent()}
var pend=[],MAXMB=window.NEORA_CONFIG.maxUploadMb||4,MAXB=MAXMB*1024*1024;
function fmtSize(n){return n>=1048576?(n/1048576).toFixed(1)+' MB':Math.max(1,Math.round(n/1024))+' KB'}
function upload(f,onP){return new Promise(function(res,rej){
 var x=new XMLHttpRequest();x.open('POST',window.NEORA_CONFIG.uploadUrl||'/api/upload');
 x.setRequestHeader('Content-Type','application/octet-stream');x.setRequestHeader('X-File-Name',encodeURIComponent(f.name));x.timeout=300000;
 x.upload.onprogress=function(e){if(e.lengthComputable&&onP)onP(Math.min(100,Math.round(e.loaded*100/e.total)))};
 x.onload=function(){var j={};try{j=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300&&j.id)res(j);else rej(new Error(j.error||('Upload failed ('+x.status+').')))};
 x.onerror=function(){rej(new Error('Could not reach the server.'))};x.ontimeout=function(){rej(new Error('Upload timed out.'))};
 x.send(f)})}
function fresh(){pend.length=0;cur={id:Date.now(),t:'',m:[]};wm.textContent='';show();drawer(0)}
function rect(){var r=(src||$('.composer')).getBoundingClientRect();return'inset('+r.top+'px '+(innerWidth-r.right)+'px '+(innerHeight-r.bottom)+'px '+r.left+'px round 22px)'}
function openWs(s,fromAsk){if(ws.classList.contains('open'))return;var wasField=isField(document.activeElement);src=s||$('.composer');try{history.pushState({ws:1},'',location.href)}catch(e){}ws.classList.add('open');ws.setAttribute('aria-hidden','false');document.body.classList.add('lock');fit();fitOn();setTimeout(fit,120);setTimeout(fit,450);
 if(!reduce){ws.animate([{clipPath:rect(),opacity:.4},{clipPath:'inset(0px 0px 0px 0px round 0px)',opacity:1}],{duration:650,easing:E1});
  $$('.wh,.hi,.wc',ws).forEach(function(e,i){e.animate([{opacity:0,transform:'translateY(14px)'},{opacity:1,transform:'none'}],{duration:500,delay:220+i*70,easing:E2,fill:'backwards'})})}
 if(!fromAsk||wasField)wi.focus({preventScroll:true})}
function closeWs(p){if(!ws.classList.contains('open'))return;if(!p&&history.state&&history.state.ws){selfBack=1;history.back();setTimeout(function(){if(ws.classList.contains('open')){selfBack=0;closeWs(1)}},350);return}drawer(0);mm(0);if(document.activeElement)document.activeElement.blur();
 function done(){stopVoice();fitOff();ws.style.height='';ws.style.transform='';ws.classList.remove('open');ws.setAttribute('aria-hidden','true');document.body.classList.remove('lock')}
 if(reduce)return done();var a=ws.animate([{clipPath:'inset(0px 0px 0px 0px round 0px)',opacity:1},{clipPath:rect(),opacity:.4}],{duration:480,easing:E1,fill:'forwards'});a.onfinish=function(){done();a.cancel()}}
async function ask(q,s){q=(q||'').trim();if(!q)return;if(busy){pend.push(q);wi.value=ta.value=inp.value='';toast(window.NEORA_STATUS?window.NEORA_STATUS.t(window.NEORA_STATUS.detect(q),'queued'):'Queued: Neora will answer next');return}busy=1;stopVoice();openWs(s,1);wi.value=ta.value=inp.value='';
 var files=atts.slice(),shown=q,qa=q;
 if(files.length){atts=[];renderAtt();shown=q+'\n[attached: '+files.map(function(x){return x.name}).join(', ')+']'}
 if(!cur.t)cur.t=parseAtt(shown).t.trim().slice(0,42)||'Attachment';
 cur.m.push(['u',[shown]]);show();add('u',shown,0,wm).parentNode.classList.add('in');
 var b=add('a','Thinking…',0,wm);b.parentNode.classList.add('in');b.classList.add('think');b.innerHTML='<span class="stw"><span class="dots"><i></i><i></i><i></i></span><span class="stl"></span></span><div class="sd"></div>';
 var S=window.NEORA_STATUS,lg=S?S.detect(shown):'en',stl=b.querySelector('.stl'),sdd=b.querySelector('.sd');
 function setSt(s){if(!S)return;var t=S.text(lg,s);stl.textContent=t.label;sdd.textContent=t.detail;sdd.className='sd'+(s&&s.k=='run'?' mono':'')}
 setSt({k:'think'});
 if(files.length){
  var tr=lg=='tr',ups=[];
  try{
   for(var ai=0;ai<files.length;ai++){
    var af=files[ai].file;
    if(!af)throw new Error(tr?'Dosya bellekte bulunamadı.':'File not found in memory.');
    if(af.size>MAXB)throw new Error(af.name+(tr?' '+MAXMB+' MB sınırını aşıyor.':' exceeds the '+MAXMB+' MB limit.'));
    var pre=(tr?'Dosya yükleniyor':'Uploading file')+(files.length>1?' '+(ai+1)+'/'+files.length:'');
    stl.textContent=pre+'…';sdd.textContent=af.name+' · '+fmtSize(af.size);sdd.className='sd';
    var uj=await upload(af,function(p){stl.textContent=pre+' · %'+p});
    ups.push({id:uj.id,name:uj.name||af.name});
   }
   stl.textContent=tr?'✓ Dosya sunucuya ulaştı':'✓ File received';sdd.textContent=tr?'Yalıtılmış sandbox içinde analiz başlıyor…':'Starting analysis in the isolated sandbox…';
   await sleep(700);
   qa=q+'\n'+ups.map(function(x){return '[uploaded_file: '+x.id+'; name: '+x.name+']'}).join('\n');
   files.forEach(function(x){if(x.url)URL.revokeObjectURL(x.url)});
   setSt({k:'think'});
  }catch(ue){
   var em=String(ue&&ue.message||(tr?'Dosya yüklenemedi.':'Upload failed.')),eo=['## '+(tr?'Dosya gönderilemedi':'Upload failed'),em,'~ '+(tr?'Dosya hâlâ ekli, tekrar gönderebilirsin.':'Your file is still attached; you can send it again.')];
   b.classList.remove('think');b.textContent='';eo.forEach(function(l){line(b,l)});cur.m.push(['a',eo]);save();
   atts=files;renderAtt();toast(em);busy=0;if(pend.length)ask(pend.shift());return}
 }
 var out=null;try{if(window.NEORA_AGENT)out=await window.NEORA_AGENT(qa,!!deep,model,setSt)}catch(e){}
 await sleep(deep?1300:700);out=out||plan(q);b.classList.remove('think');b.textContent='';
 for(var i=0;i<out.length;i++){line(b,out[i]);wb.scrollTop=wb.scrollHeight;await sleep(out.length>12?60:260)}
 cur.m.push(['a',out]);save();busy=0;if(pend.length)ask(pend.shift())}
function go(v,s){v=(v||'').trim();v?ask(v,s):openWs(s)}
var bar=$('.bar');
$('#go').onclick=function(){go(cmp(ta.value))};$('#go2').onclick=function(){go(inp.value,bar)};$('#wgo').onclick=function(){go(cmp(wi.value))};
ta.onkeydown=function(e){if(e.key=='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();go(cmp(ta.value))}};
inp.onkeydown=function(e){if(e.key=='Enter'&&!e.isComposing)go(inp.value,bar)};wi.onkeydown=function(e){if(e.key=='Enter'&&!e.isComposing)ask(cmp(wi.value))};

$('#deep').onclick=function(){setDeep(!deep)};
/* ---------- model picker ---------- */
var MODELS=window.NEORA_CONFIG.models,SPEECH=window.NEORA_CONFIG.speechModel;
var mdl=$('#mdl'),mdd=$('#mdd'),model=(MODELS.filter(function(m){return m.id==lsGet('neora.model')})[0]||MODELS[0]).id;
function mObj(){return MODELS.filter(function(m){return m.id==model})[0]||MODELS[0]}
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function ckSvg(){var N='http://www.w3.org/2000/svg',s=document.createElementNS(N,'svg'),p=document.createElementNS(N,'path');s.setAttribute('viewBox','0 0 24 24');s.setAttribute('class','ic ck');s.setAttribute('aria-hidden','true');p.setAttribute('d','M5 12.5l4.5 4.5L19 7.5');s.append(p);return s}
function row(role,name,tag,desc,idTxt,dim){var b=el('button','mi'),t=el('span','mt');b.type='button';b.setAttribute('role',role);t.append(el('b','',name));if(tag)t.append(el('em','tg'+(dim?' dim':''),tag));b.append(t);if(desc)b.append(el('span','md',desc));if(idTxt)b.append(el('code','',idTxt));return b}
function mdBuild(){mdd.textContent='';mdd.append(el('small','','Model'));
 MODELS.forEach(function(m){var b=row('menuitemradio',m.name,m.tag,m.d,m.id);b.dataset.id=m.id;b.append(ckSvg());mdd.append(b)});
 mdd.append(el('hr'));mdd.append(el('small','','Voice input'));
 var s=row('menuitemradio',SPEECH.name,'Soon',SPEECH.d,SPEECH.id,1);s.setAttribute('aria-disabled','true');s.setAttribute('aria-checked','false');mdd.append(s);
 mdd.append(el('hr'));
 var d=row('menuitemcheckbox','Deep mode',0,'Slower, more thorough analysis');d.dataset.k='deep';d.append(el('i','tgl'));mdd.append(d);mdSync()}
function mdSync(){$$('.mi',mdd).forEach(function(b){if(b.dataset.id)b.setAttribute('aria-checked',b.dataset.id==model);else if(b.dataset.k=='deep')b.setAttribute('aria-checked',!!deep)})}
function lab(){$('#mn').textContent=mObj().name+(deep?' \u00b7 Deep':'')}
function setModel(id){model=id;lsSet('neora.model',id);lab();mdSync();toast('Model: '+mObj().name)}
function mm(o,kb){o=!!o;if(o===mdd.classList.contains('open'))return;mdd.classList.toggle('open',o);mdl.setAttribute('aria-expanded',o);mdd.setAttribute('aria-hidden',!o);
 if(o){ws.classList.remove('sb');if(kb)setTimeout(function(){var f=$('.mi[aria-checked=true][data-id]',mdd)||$('.mi',mdd);if(f)f.focus({preventScroll:true})},60)}
 else if(mdd.contains(document.activeElement))mdl.focus({preventScroll:true})}
mdBuild();
mdl.onclick=function(e){mm(!mdd.classList.contains('open'),e.detail===0)};
mdl.addEventListener('keydown',function(e){if(e.key=='ArrowDown'){e.preventDefault();mm(1,1)}});
mdd.onclick=function(e){var b=e.target.closest('.mi');if(!b)return;
 if(b.getAttribute('aria-disabled')=='true'){toast('Speech model: voice input coming soon');return}
 if(b.dataset.id){setModel(b.dataset.id);setTimeout(function(){mm(0)},160)}else if(b.dataset.k=='deep')setDeep(!deep)};
mdd.addEventListener('keydown',function(e){var k=e.key;if(k!='ArrowDown'&&k!='ArrowUp'&&k!='Home'&&k!='End')return;e.preventDefault();
 var L=$$('.mi:not([aria-disabled=true])',mdd),i=L.indexOf(document.activeElement);i=k=='Home'?0:k=='End'?L.length-1:k=='ArrowDown'?(i+1)%L.length:(i<=0?L.length-1:i-1);L[i].focus()});
/* Esc closes the picker first, not the whole workspace */
addEventListener('keydown',function(e){if(e.key=='Escape'&&mdd.classList.contains('open')){e.stopPropagation();mm(0)}},true);
document.addEventListener('pointerdown',function(e){if(mdd.classList.contains('open')&&!e.target.closest('#mdd,#mdl'))mm(0)},true);
$('#x').onclick=function(){closeWs()};$('#menuB').onclick=function(){drawer(!ws.classList.contains('sb'))};$('#newB').onclick=$('#nc').onclick=fresh;
$('#clr').onclick=function(){lsSet(K,'[]');recent()};
$('.wmain').onclick=function(e){if(ws.classList.contains('sb')&&!e.target.closest('#menuB'))drawer(0)};
$$('.sg button').forEach(function(b){b.onclick=function(){ask(b.textContent)}});
$('#add').onclick=function(){ft=ta;$('#file').click()};$('#wadd').onclick=function(){ft=wi;$('#file').click()};
var atts=[],trH=document.createElement('div'),trW=document.createElement('div');trH.className=trW.className='att-tray';ta.parentNode.insertBefore(trH,ta);var wpl=$('.wpill');wpl.parentNode.insertBefore(trW,wpl);
function attCard(n,url,i){var c=document.createElement('div'),ic=document.createElement('span'),tx=document.createElement('span'),nm=document.createElement('span'),ty=document.createElement('span'),x=n.lastIndexOf('.');c.className='att';ic.className='att-i';
 if(url){var im=document.createElement('img');im.src=url;im.alt='';ic.append(im)}else ic.innerHTML='<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>';
 tx.className='att-x';nm.className='att-n';nm.textContent=n;nm.title=n;ty.className='att-t';ty.textContent=x>0&&x<n.length-1?n.slice(x+1,x+6).toUpperCase():'FILE';tx.append(nm,ty);c.append(ic,tx);
 if(i!=null){var b=document.createElement('button');b.type='button';b.className='att-rm';b.setAttribute('aria-label','Remove '+n);b.dataset.i=i;b.innerHTML='<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';c.append(b)}return c}
function parseAtt(l){l=String(l);var m=/(?:\n|^)\[attached: ([^\]]*)\]\s*$/.exec(l);return m?{t:l.slice(0,m.index),f:m[1].split(', ')}:{t:l,f:[]}}
function renderAtt(){[trH,trW].forEach(function(t){t.textContent='';atts.forEach(function(a,i){t.append(attCard(a.name,a.url,i))})});if(ws.classList.contains('open'))requestAnimationFrame(fit)}
function cmp(v){v=(v||'').trim();return v|| (atts.length?'Please analyze the attached file(s) and tell me if they are safe.':'')}
[trH,trW].forEach(function(t){t.onclick=function(e){var b=e.target.closest('.att-rm');if(!b)return;var a=atts.splice(+b.dataset.i,1)[0];if(a&&a.url)URL.revokeObjectURL(a.url);renderAtt()}});
$('#file').onchange=function(){var n=0;Array.from(this.files).forEach(function(f){if(f.size>MAXB){toast(f.name+' > '+MAXMB+' MB');return}if(atts.some(function(a){return a.name==f.name&&a.size==f.size}))return;atts.push({name:f.name,size:f.size,file:f,url:/^image\//.test(f.type)?URL.createObjectURL(f):''});n++});if(n){renderAtt();toast('File added \u00b7 press send to upload and analyze (max '+MAXMB+' MB each)')}this.value=''};
$('.shell').insertAdjacentHTML('afterend','<div class="try" data-enter><button>Should we build or buy this tool?</button><button>Analyze why signups dropped</button><button>Help me plan a product launch</button></div>');
$$('.try button').forEach(function(b){b.onclick=function(){ask(b.textContent)}});
setDeep(lsGet('neora.deep')=='1');fresh();recent();
var tt;function toast(t){var e=$('.toast');e.textContent=t;e.classList.add('on');clearTimeout(tt);tt=setTimeout(function(){e.classList.remove('on')},2400)}
var SR=window.SpeechRecognition||window.webkitSpeechRecognition,rec=null,vb=null,vt=null,base='',skip=0,rl=0,vwant=false;
function vset(txt){var sep=base&&txt&&!/\s$/.test(base)?' ':'';vt.value=base+sep+txt}
function vmark(){$$('.mic').forEach(function(m){m.classList.toggle('rec',vwant&&m===vb)})}
function stopVoice(){vwant=false;vmark();vb=vt=null;if(rec){try{rec.abort()}catch(e){}}}
/* one recognizer for the whole page: the browser asks for the microphone once, not on every tap */
function getRec(){if(rec)return rec;var r=rec=new SR();r.continuous=true;r.interimResults=true;r.lang=navigator.language||'en-US';
 r.onresult=function(e){if(!vwant||!vt)return;rl=e.results.length;var a=[];for(var i=skip;i<rl;i++)a.push(e.results[i][0].transcript);vset(a.join(''))};
 r.onerror=function(e){if(e.error=='not-allowed'||e.error=='service-not-allowed'){stopVoice();toast('Microphone is blocked. Allow it in the site settings.')}else if(e.error=='audio-capture'){stopVoice();toast('No microphone found')}};
 r.onend=function(){vwant=false;vmark()};
 return r}
function startVoice(b){var t=b.dataset.t=='w'?wi:b.dataset.t=='2'?inp:ta;vb=b;vt=t;base=t.value;skip=0;rl=0;vwant=true;vmark();
 try{getRec().start()}catch(e){if(e.name=='InvalidStateError'){setTimeout(function(){try{rec.start()}catch(_){stopVoice();toast('Voice input unavailable')}},250)}else{stopVoice();toast('Voice input unavailable')}}}
$$('.mic').forEach(function(b){b.onclick=function(){
 if(!SR)return toast('Voice input isn’t supported in this browser. Try Chrome, Edge or Safari.');
 if(vwant&&vb===b){stopVoice();return}
 if(vwant){stopVoice();setTimeout(function(){startVoice(b)},250);return}
 startVoice(b)}});
/* typing while the mic is on: keep what was typed, only add new speech after it */
[ta,inp,wi].forEach(function(el){el.addEventListener('input',function(){if(vwant&&vt===el){base=el.value;skip=rl}})});
document.addEventListener('visibilitychange',function(){if(document.hidden)stopVoice()});

var vv=window.visualViewport,fitRaf=0,maxH=0,maxW=0,kbOpen=false,kbClosedAt=0,selfBack=0,coarse=matchMedia('(pointer:coarse)').matches;
function isField(a){return!!a&&(a.tagName=='INPUT'||a.tagName=='TEXTAREA')}
/* keyboard state from the visual viewport; when it closes, drop focus so the next Back press leaves the chat normally */
function kbTrack(){if(!vv)return;if(innerWidth!=maxW){maxW=innerWidth;maxH=0}var vh=vv.height;if(vh>maxH)maxH=vh;var o=maxH-vh>120;if(o===kbOpen)return;kbOpen=o;
 if(o){if(ws.classList.contains('open'))wb.scrollTop=wb.scrollHeight}
 else{kbClosedAt=Date.now();var a=document.activeElement;if(ws.classList.contains('open')&&isField(a)&&ws.contains(a))a.blur()}}
function doFit(){fitRaf=0;kbTrack();if(!ws.classList.contains('open'))return;ws.scrollTop=ws.scrollLeft=0;var m=ws.querySelector('.wmain');if(m)m.scrollTop=m.scrollLeft=0;if(!vv)return;
 var h=Math.round(vv.height)+'px',ty=Math.round(vv.offsetTop),t=ty>0?'translateY('+ty+'px)':'';if(ws.style.height!==h)ws.style.height=h;if(ws.style.transform!==t)ws.style.transform=t}
function fit(){if(!fitRaf)fitRaf=requestAnimationFrame(doFit)}
function fitOn(){}function fitOff(){}
ws.addEventListener('scroll',function(){ws.scrollTop=ws.scrollLeft=0});
addEventListener('resize',fit);addEventListener('orientationchange',function(){maxH=0;setTimeout(fit,200)});
if(vv){vv.addEventListener('resize',fit);vv.addEventListener('scroll',function(){if(ws.classList.contains('open'))fit()})}
[wi,ta,inp].forEach(function(el){['focus','blur'].forEach(function(ev){el.addEventListener(ev,function(){setTimeout(fit,120);setTimeout(fit,450)})})});
/* keep the keyboard up while tapping Send / attach, so it does not flicker */
$$('.send,.pb').forEach(function(b){b.addEventListener('mousedown',function(e){if(isField(document.activeElement))e.preventDefault()})});

/* ---------- menu ---------- */
var ov=$('#ov'),bg=$('.burger');
function menu(o){var was=ov.classList.contains('open'),inside=ov.contains(document.activeElement);ov.classList.toggle('open',o);if(o)setTimeout(function(){$('#ovx').focus({preventScroll:true})},60);else if(was&&inside)bg.focus({preventScroll:true});ov.setAttribute('aria-hidden',!o);bg.setAttribute('aria-expanded',o);document.body.classList.toggle('menu-open',o)}
bg.onclick=function(){menu(bg.getAttribute('aria-expanded')!='true')};
addEventListener('keydown',function(e){if(e.key=='Escape'){closeWs();menu(false)}});
addEventListener('popstate',function(){
 if(selfBack){selfBack=0;closeWs(1);return}
 if(ws.classList.contains('open')&&(kbOpen||Date.now()-kbClosedAt<900||(coarse&&isField(document.activeElement)&&ws.contains(document.activeElement)))){
  try{history.pushState({ws:1},'',location.href)}catch(e){}
  var a=document.activeElement;if(isField(a)&&ws.contains(a))a.blur();return}
 closeWs(1)});
addEventListener('resize',function(){if(innerWidth>1024)menu(false)});
$('#ovx').onclick=function(){menu(false)};

/* ---------- containments dialog ---------- */
var cm=$('#cm'),cmFrom=null;
function contain(o,from){if(o===cm.classList.contains('open'))return;
 if(o){cmFrom=from||null;cm.classList.add('open');cm.setAttribute('aria-hidden','false');document.body.classList.add('cm-open');setTimeout(function(){$('#cmx').focus({preventScroll:true})},60)}
 else{var f=cmFrom&&!ov.contains(cmFrom)&&cmFrom.offsetParent?cmFrom:(bg.offsetParent?bg:null),inside=cm.contains(document.activeElement);cm.classList.remove('open');cm.setAttribute('aria-hidden','true');document.body.classList.remove('cm-open');cmFrom=null;if(inside&&f)f.focus({preventScroll:true})}}
$$('[data-contain]').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();menu(false);contain(true,a)})});
$('#cmx').onclick=function(){contain(false)};
cm.addEventListener('click',function(e){if(e.target===cm)contain(false)});
addEventListener('keydown',function(e){if(!cm.classList.contains('open'))return;
 if(e.key=='Escape'){contain(false);return}
 if(e.key=='Tab'){var x=$('#cmx'),b=$('#cmb'),a=document.activeElement;if(e.shiftKey&&a===x){e.preventDefault();b.focus()}else if(!e.shiftKey&&a===b){e.preventDefault();x.focus()}else if(!cm.contains(a)){e.preventDefault();x.focus()}}});
$$('#ov a').forEach(function(a){a.addEventListener('click',function(){menu(false)})});
$$('[data-try]').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();menu(false);fresh();openWs(a)})});

/* ---------- entrance choreography (WAAPI) ---------- */
function mk(){var A=[];
 function an(e,k,d,t,x){if(e)A.push(e.animate(k,{duration:d*1e3,delay:t*1e3,easing:x||E2,fill:'both'}))}
 function lift(e,y,d,t){an(e,[{opacity:0,transform:'translateY('+y*M+'px)'},{opacity:1,transform:'none'}],d,t)}
 function mask(e,t){an(e,[{opacity:0,transform:'translateY(108%)'},{opacity:1,offset:.14},{opacity:1,transform:'none'}],.95,t,E1)}
 return{an:an,lift:lift,mask:mask,end:function(f){Promise.all(A.map(function(a){return a.finished})).then(function(){A.forEach(function(a){a.cancel()});f()}).catch(f)}}}
function hero(){var t=mk();
 t.an($('[data-badge]'),[{opacity:0,transform:'scale(.9)'},{opacity:1,transform:'none'}],.7,.12);
 t.an($('.brand'),[{opacity:0,transform:'scale(.92)'},{opacity:1,transform:'none'}],.6,0);
 $$('.nav a').forEach(function(e,i){t.lift(e,10,.5,.1+i*.05)});t.lift($('.burger'),10,.5,.16);t.lift($('.top .cta'),10,.5,.26);
 $$('.s1 .hl-line').forEach(function(e,i){t.mask(e,.2+i*.09)});t.lift($('.s1 .sub'),14,.65,.52);
 t.an($('.shell'),[{opacity:0,transform:'translateY('+22*M+'px) scale(.985)'},{opacity:1,transform:'none'}],.95,.64,E1);
 t.lift(ta,10,.55,.78);$$('.ctl>[data-enter]').forEach(function(e,i){t.lift(e,10,.55,.84+i*.055)});
 t.an($('.glow'),[{clipPath:'inset(0 40% 0 40%)',opacity:0},{clipPath:'inset(0 0% 0 0%)',opacity:.95}],.8,.94,E1);
 t.lift($('.try'),10,.55,1.0);$$('.trust span').forEach(function(e,i){t.lift(e,12,.6,1.08+i*.06)});
 t.end(function(){D.classList.remove('entrance');D.classList.add('hero-ready')})}
function s2(){if(s2d||!D.classList.contains('entrance-s2'))return;s2d=1;var t=mk();
 $$('.s2 .hl-line').forEach(function(e,i){t.mask(e,i*.09)});t.lift($('.s2 .sub'),14,.65,.3);
 t.an($('.panel'),[{opacity:0,transform:'translateY('+26*M+'px) scale(.985)'},{opacity:1,transform:'none'}],1,.4,E1);
 t.lift($('.live'),10,.55,.68);t.an($('.chat'),[{transform:'translateY('+18*M+'px)'},{transform:'none'}],.85,.72,E1);
 $$('.m[data-enter]').forEach(function(e,i){t.lift(e,10,.55,.88+i*.065)});t.lift($('.bar'),10,.55,1.24);
 t.end(function(){D.classList.remove('entrance-s2')})}
if(D.classList.contains('entrance')){Promise.race([document.fonts.ready,sleep(400)]).then(hero);
 var io=new IntersectionObserver(function(es){if(es.some(function(e){return e.isIntersecting})){io.disconnect();s2()}},{rootMargin:'0px 0px -20% 0px',threshold:0});io.observe($('#s2'))}
if(!reduce&&'IntersectionObserver' in window){var rv=$$('.how div');rv.forEach(function(e,i){e.classList.add('rv');e.style.setProperty('--d',i*90+'ms')});
 var ro=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in');ro.unobserve(e.target)}})},{rootMargin:'0px 0px -8% 0px'});rv.forEach(function(e){ro.observe(e)})}
})();
