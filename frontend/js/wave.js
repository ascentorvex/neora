/* Neora - WebGL wave background for the hero */
(function(){
var c=document.getElementById('wave');if(!c)return;
var gl=c.getContext('webgl',{antialias:false,alpha:false,powerPreference:'low-power'});
if(!gl){c.classList.add('nogl');return}
var vs='attribute vec2 a;void main(){gl_Position=vec4(a,0.,1.);}';
var fs=`precision highp float;
uniform vec2 R;uniform float T,P,D,K,G;
float h(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
float vn(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(h(i),h(i+vec2(1.,0.)),f.x),mix(h(i+vec2(0.,1.)),h(i+vec2(1.,1.)),f.x),f.y);}
void edges(float x,float t,float ph,out float a,out float b){
 float c=.5+.05*sin(x*1.7+t*.21+ph);
 float w1=x*5.3+t*.5+ph,w2=x*2.2-t*.33+ph*1.7;
 a=c+G*(.23*sin(w1)+.12*sin(w2+1.))-.1*G;
 b=c+G*(.23*sin(w1+1.9)+.12*sin(w2+2.6))+.1*G+.12;
}
void main(){
 vec2 fc=gl_FragCoord.xy;vec2 uv=fc/R;float t=T;
 float x=mix(uv.x,.02+uv.x*.85,P);
 float y=(1.-uv.y)/K;
 vec2 g=floor(fc/D);float r=h(g);
 float nz=vn(vec2(x,y)*12.+t*.04)*.5+vn(vec2(x,y)*48.)*.25;
 float a,b;edges(x,t,0.,a,b);
 float d=b-a,v=(y-a)/(abs(d)<.0001?.0001:d);
 float lo=min(a,b),hi=max(a,b);
 float inside=step(lo,y)*step(y,hi);
 float m=inside*min(v,1.-v)*abs(d);
 float outd=max(lo-y,y-hi);outd=max(outd,0.);
 float glow=exp(-outd*16.)*(1.-inside);
 float dens=smoothstep(-.004,.05,m+(nz-.4)*.03)*inside;
 float vis=clamp(step(r,dens)*inside+(1.-inside)*step(r*2.2,glow*.5),0.,1.);
 float face=d>0.?1.:-1.;
 float vv=face>0.?v:1.-v;
 float br=.28+.62*pow(clamp(1.-vv,0.,1.),1.25);
 br+=exp(-pow(abs(d)/.04,1.2))*.6;
 br+=exp(-min(v,1.-v)*abs(d)*60.)*.18*inside;
 br*=.9+.14*h(g+7.3);
 br*=.94+.1*vn(fc*.04/D+t*.1);
 br=clamp(br,0.,1.);
 float a2,b2;edges(x+.1,t*.8,2.2,a2,b2);
 float lo2=min(a2,b2),hi2=max(a2,b2);
 float in2=step(lo2,y)*step(y,hi2);
 float g2=in2*smoothstep(0.,.05,min((y-lo2),(hi2-y)))*.22;
 vec3 col=vec3(br*.98,br,br*1.03)*vis;
 col+=vec3(.55)*g2*(1.-vis)*(.8+.4*h(g+2.));
 vec2 sc=fc/(13.*D);vec2 sg=floor(sc);
 vec2 off=vec2(h(sg+9.),h(sg+17.))-.5;
 float dd=length(fract(sc)-.5-off*.6);
 float star=step(.9,h(sg*1.7+3.1))*smoothstep(.1,.03,dd)*(.3+.7*h(sg+2.))*(.65+.35*sin(t*(1.+h(sg+5.)*2.)+h(sg)*30.));
 vec2 sc2=fc/(5.*D);vec2 sg2=floor(sc2);
 float dust=step(.972-glow*.08,h(sg2+31.))*smoothstep(.22,.05,length(fract(sc2)-.5))*.4;
 col+=vec3(star+dust)*(1.-vis);
 col*=1.-.75*smoothstep(1.,1.45,y);
 col*=smoothstep(0.,.12,uv.y);
 gl_FragColor=vec4(col,1.);
}`;
function mk(t,src){var o=gl.createShader(t);gl.shaderSource(o,src);gl.compileShader(o);if(!gl.getShaderParameter(o,gl.COMPILE_STATUS))console.warn(gl.getShaderInfoLog(o));return o}
var pr,uR,uT,uP,uK,uG,uD;
function init(){pr=gl.createProgram();gl.attachShader(pr,mk(gl.VERTEX_SHADER,vs));gl.attachShader(pr,mk(gl.FRAGMENT_SHADER,fs));gl.linkProgram(pr);
if(!gl.getProgramParameter(pr,gl.LINK_STATUS))return false;
gl.useProgram(pr);
var b=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,b);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,3,-1,-1,3]),gl.STATIC_DRAW);
var a=gl.getAttribLocation(pr,'a');gl.enableVertexAttribArray(a);gl.vertexAttribPointer(a,2,gl.FLOAT,false,0,0);
uR=gl.getUniformLocation(pr,'R');uT=gl.getUniformLocation(pr,'T');uP=gl.getUniformLocation(pr,'P');uK=gl.getUniformLocation(pr,'K');uG=gl.getUniformLocation(pr,'G');uD=gl.getUniformLocation(pr,'D');return true}
if(!init()){c.classList.add('nogl');return}
var still=matchMedia('(prefers-reduced-motion: reduce)').matches,mob=innerWidth<700,t0=performance.now(),first=1,raf=0,vis=true,lost=false,last=0,fr=0,ds=0,q=mob?.8:1;
function draw(){var el=(performance.now()-t0)/1000;gl.uniform1f(uG,still?1:.55+.45*(1-Math.exp(-el*.5)));gl.uniform1f(uT,still?4:el+4);gl.drawArrays(gl.TRIANGLES,0,3);if(first){first=0;c.classList.add('on')}}
function size(){if(lost)return;var d=Math.min(devicePixelRatio||1,mob?1.25:1.75)*q,w=c.clientWidth,h=c.clientHeight;if(!w||!h)return;c.width=Math.round(w*d);c.height=Math.round(h*d);gl.viewport(0,0,c.width,c.height);gl.uniform2f(uR,c.width,c.height);gl.uniform1f(uP,w/h<.85?1:0);gl.uniform1f(uD,d);var hh=document.querySelector('.s1 h1'),k=1;if(hh){k=(hh.getBoundingClientRect().top-c.getBoundingClientRect().top)/h*(w/h<.85?1.25:1.75);k=Math.max(.5,Math.min(.68,k))}gl.uniform1f(uK,k);draw()}
/* draw only while the hero is on screen, the tab is visible and no overlay covers it */
function should(){var b=document.body.classList;return!still&&vis&&!lost&&!document.hidden&&!b.contains('lock')&&!b.contains('menu-open')}
function loop(n){raf=0;if(!should())return;raf=requestAnimationFrame(loop);if(mob&&n-last<33)return;var dt=last?n-last:0;last=n;draw();if(dt&&dt<400&&q>.55){ds+=dt;fr++;if(fr==24){if(ds/fr>(mob?58:45)){q=.55;size()}fr=0;ds=0}}}
function kick(){if(!raf&&should()){last=0;raf=requestAnimationFrame(loop)}}
if('IntersectionObserver' in window)new IntersectionObserver(function(es){vis=es[es.length-1].isIntersecting;kick()},{threshold:0}).observe(c);
if('MutationObserver' in window)new MutationObserver(kick).observe(document.body,{attributes:true,attributeFilter:['class']});
document.addEventListener('visibilitychange',kick);
c.addEventListener('webglcontextlost',function(e){e.preventDefault();lost=true;cancelAnimationFrame(raf);raf=0});
c.addEventListener('webglcontextrestored',function(){lost=false;if(init()){size();kick()}else c.classList.add('nogl')});
size();if(window.ResizeObserver)new ResizeObserver(size).observe(c);else addEventListener('resize',size);if(document.fonts&&document.fonts.ready)document.fonts.ready.then(size);
kick();
})();
