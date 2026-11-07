/* Neora - button ripple, send-button state, lite mode for weak devices */
(function(){
var rm=matchMedia('(prefers-reduced-motion: reduce)').matches;
/* ripple + haptic tick */
document.addEventListener('pointerdown',function(e){if(rm)return;var b=e.target.closest('.send,.cta,.chip,.try button,.sg button,.pb,.mic,.wh button,.side button,.mi');if(!b||b.getAttribute('aria-disabled')=='true')return;
 var r=b.getBoundingClientRect(),d=Math.max(r.width,r.height)*2.2,s=document.createElement('span');s.className='rip';
 s.style.cssText='width:'+d+'px;height:'+d+'px;left:'+(e.clientX-r.left-d/2)+'px;top:'+(e.clientY-r.top-d/2)+'px';b.appendChild(s);setTimeout(function(){s.remove()},700)},{passive:true});
document.addEventListener('click',function(e){var b=e.target.closest('.send');if(!b)return;try{navigator.vibrate&&navigator.vibrate(8)}catch(_){}
 var u=b.querySelector('.up');if(u&&!rm){u.classList.remove('fly');void u.getBoundingClientRect();u.classList.add('fly');setTimeout(function(){u.classList.remove('fly')},650)}});
/* dim Send when the field is empty (chat boxes only) */
var pairs=[['q2','go2'],['wi','wgo']];
function upd(){pairs.forEach(function(p){var i=document.getElementById(p[0]),b=document.getElementById(p[1]);if(i&&b)b.classList.toggle('idle',!i.value.trim())})}
document.addEventListener('input',upd);document.addEventListener('click',function(){setTimeout(upd,60)});
setInterval(function(){if(!document.hidden&&document.querySelector('.mic.rec'))upd()},400);
document.addEventListener('keydown',function(){setTimeout(upd,60)});upd();
/* weaker devices: keep the look, drop the costliest effects */
var cn=navigator.connection||{};if(navigator.hardwareConcurrency<=4||navigator.deviceMemory<=2||cn.saveData)document.documentElement.classList.add('lite');
})();
