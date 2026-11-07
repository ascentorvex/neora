/* Neora - agent client.
   Sends {url, goal, model, deep, lang} to the backend and turns the answer into chat lines.
   All connection settings live in config/neora.config.js. */
(function(){
var cfg=window.NEORA_CONFIG;
function sleep(ms){return new Promise(function(r){setTimeout(r,ms)})}
/* Job mode: start a job, then poll its live status until the result is ready (no proxy time limit).
   Falls back to the classic single request when the job API is not available. */
async function call(body,onStatus,signal){
 var h={'Content-Type':'application/json'},st=null;
 if(cfg.startUrl&&cfg.jobUrl){
  try{var s=await fetch(cfg.startUrl,{method:'POST',headers:h,body:JSON.stringify(body),signal:signal});
   if(s.status!==404&&s.status!==405)st={s:s,j:await s.json().catch(function(){return{}})}}
  catch(e){if(e.name==='AbortError')throw e}
 }
 if(st){
  if(!st.s.ok||!st.j.id)return{ok:false,status:st.s.status,j:st.j};
  var last='',fails=0;
  for(;;){
   await sleep(900);
   var p;try{p=await fetch(cfg.jobUrl+'?id='+encodeURIComponent(st.j.id),{signal:signal})}catch(e){if(e.name==='AbortError'||++fails>5)throw e;continue}
   var pj=await p.json().catch(function(){return{}});
   if(!p.ok)return{ok:false,status:p.status,j:pj};
   if(pj.status&&onStatus){var key=pj.status.k+'|'+pj.status.d;if(key!==last){last=key;try{onStatus(pj.status)}catch(e){}}}
   if(pj.state==='done')return{ok:true,status:200,j:pj.result||{}};
   if(pj.state==='error')return{ok:false,status:pj.code||500,j:{error:pj.error}};
  }
 }
 var r=await fetch(cfg.apiUrl,{method:'POST',headers:h,body:JSON.stringify(body),signal:signal});
 return{ok:r.ok,status:r.status,j:await r.json().catch(function(){return{}})};
}
window.NEORA_AGENT=async function(q,deep,model,onStatus){
 if(location.protocol==='https:'&&/^http:/i.test(cfg.apiUrl))return['## Couldn’t reach the agent','This page is served over HTTPS but the API URL is plain HTTP, and browsers block that. Set apiUrl to "/api/analyze" in config/neora.config.js and enable the nginx proxy (see README).'];
 var qs=q.replace(/\[uploaded_file:[^\]]*\]/g,' '),m=qs.match(/https?:\/\/[^\s<>"')]+/i)||qs.match(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ai|dev|app|co|edu|gov|tr|info|me|xyz|tech|cloud)\b(?:\/[^\s<>"')]*)?/i),url=m?(/^https?:/i.test(m[0])?m[0]:'https://'+m[0]):'',goal=q.trim();
 var S=window.NEORA_STATUS,raw=S?S.detectRaw(q):'auto',lg=S?S.detect(q):'en',T=function(k){return S?S.t(lg,k):k};
 /* the language is decided from the user's own words BEFORE anything is sent, so the model answers in it */
 var ac=new AbortController(),to=cfg.requestTimeoutMs>0?setTimeout(function(){ac.abort()},cfg.requestTimeoutMs):0;
 try{
  var cr=await call({url:url,goal:goal,model:model,deep:!!deep,lang:raw},onStatus,ac.signal),j=cr.j||{};
  if(!cr.ok||j.error){if(j.error)try{console.warn('Neora backend:',cr.status,j.error)}catch(e){}
   return['## '+T('errT'),cr.status==429?T('rate'):cr.status==503?T('busy'):T('srv')+' ('+cr.status+')','~ '+T('retry')]}
  var t=String(j.answer||'').trim();
  if(!t)return['## '+T('emptyT'),T('emptyB')];
  var tools=[],ix=t.search(/\n+##\s*(?:Tools used|Kullanılan araçlar)\s*\n/);
  if(ix>-1){t.slice(ix).split('\n').forEach(function(l){l=l.replace(/^-\s*/,'').trim();
   if(!l||/^##/.test(l))return;
   if(l.indexOf('🧪 ')==0){try{tools.push({k:'insp',l:lg,v:JSON.parse(l.slice(3))})}catch(e){}return}
   if(l.indexOf('🛡 ')==0){if(tools.length)try{tools[tools.length-1].r=JSON.parse(l.slice(3))}catch(e){}return}
   if(l.indexOf('↳ ')==0){if(tools.length)tools[tools.length-1].o=l.slice(2).split(' ⏎ ').join('\n');return}
   var k=l.indexOf('🔎 ')==0?'search':l.indexOf('📄 ')==0?'read':l.indexOf('$ ')==0?'cmd':'';
   if(k)tools.push({k:k,l:lg,t:l.slice(k=='cmd'?2:3)})});t=t.slice(0,ix).trim()}
  var res=t.split(/\n+/).map(function(l){l=l.trim().replace(/\*\*|__|`/g,'').replace(/\*(\S[^*]*?)\*/g,'$1').replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,'$1 ($2)');
   if(/^#{1,6}\s/.test(l))return'## '+l.replace(/^#{1,6}\s+/,'');
   if(/^([-*•]|\d+[.)])\s/.test(l))return'• '+l.replace(/^([-*•]|\d+[.)])\s+/,'');
   return l}).filter(Boolean);
  if(tools.length){res.push('^ '+JSON.stringify({h:1,l:lg}));tools.forEach(function(x){res.push('^ '+JSON.stringify(x))})}
  if(j.report&&j.report.name&&j.report.content){if(!tools.length)res.push('^ '+JSON.stringify({h:1,l:lg}));res.push('^ '+JSON.stringify({l:lg,dl:{n:String(j.report.name).slice(0,80),c:String(j.report.content)}}))}
  if(j.model)res.push('~ '+T('by')+' '+String(j.model).slice(0,60));return res;
 }catch(e){
  return['## '+T('noreachT'),e.name=='AbortError'?T('timeout'):T('noreachB')];
 }finally{if(to)clearTimeout(to)}
};
})();
