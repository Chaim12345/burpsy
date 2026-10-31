// ch21: ui2 intercept rule-list toggles against live burpsy (web 18096, proxy 18095, echo victim 18101).
const { chromium } = require('/tmp/pw/node_modules/playwright-core');
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const BASE='http://127.0.0.1:18096';
const MODE=process.argv[2]||'mobile';
const LOG=[];
function log(k,v){LOG.push({k,v});console.log('LOG',k,typeof v==='string'?v.slice(0,200):v);}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function cue(page,x,y){await page.evaluate(([x,y])=>{const d=document.getElementById('__cue')||document.createElement('div');d.id='__cue';d.style.cssText=`position:fixed;left:${x-14}px;top:${y-14}px;width:28px;height:28px;border:3px solid #ff3b30;border-radius:50%;z-index:99999;pointer-events:none;box-shadow:0 0 6px #ff3b30;`;document.body.appendChild(d);},[x,y]);await sleep(700);await page.evaluate(()=>{const d=document.getElementById('__cue');if(d)d.remove();});}
async function cueEl(page,sel){try{const el=page.locator(sel).first();await el.scrollIntoViewIfNeeded();await page.mouse.move(5,5);const b=await el.boundingBox();if(b)await cue(page,b.x+b.width/2,b.y+b.height/2);}catch(e){console.log('CUE-SKIP',sel,e.message.slice(0,80));}}
function api(method,path,body){const b=body?` -H "Content-Type: application/json" -d '${JSON.stringify(body)}'`:"";return execSync(`curl -s -X ${method} ${BASE}${path}${b}`).toString();}
(async()=>{
 const __wd=setTimeout(async()=>{console.log('WATCHDOG-PARTIAL-SAVE');try{await ctx.close();}catch(e){}process.exit(2);},200000);
 const browser=await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
 const vw=MODE==='mobile'?{width:390,height:844}:{width:1280,height:800};
 const ctx=await browser.newContext({viewport:vw,recordVideo:{dir:'/tmp/vid21_'+MODE,size:vw}});
 ctx.setDefaultTimeout(25000);
 const page=await ctx.newPage();

 // arm: interception ON; request list active with one stored hold rule; response list active+empty (unconditional)
 api('POST','/api/intercept/enable',{enabled:true});
 api('PUT','/api/intercept/rules/requests',{active:true,rules:[{field:'path',category:'literal',string_match:'/ch21-hold',enabled:true,comment:'film rule',action:'hold'}]});
 api('PUT','/api/intercept/rules/responses',{active:true,rules:[]});
 api('POST','/api/intercept/drop-all');
 log('armed','interception ON; request list: 1 stored hold-rule; response list: empty (armed via API; page toggles are the feature under test)');

 // 1. page shows both lists' state and disclosures
 await page.goto(BASE+'/ui2/intercept',{waitUntil:'domcontentloaded'});await sleep(1500);
 const reqMeta=page.locator('#rows p.meta',{hasText:'Request rules'}).first();
 const resMeta=page.locator('#rows p.meta',{hasText:'Response rules'}).first();
 await reqMeta.waitFor();await resMeta.waitFor();
 const rm=await reqMeta.textContent(), sm=await resMeta.textContent();
 if(!rm.includes('ON')||!rm.includes('1 stored'))throw new Error('request list state wrong: '+rm);
 if(!sm.includes('ON')||!sm.includes('0 stored')||!sm.includes('empty list holds every response'))throw new Error('response list disclosure wrong: '+sm);
 log('state-shown','request list ON with 1 stored; response list ON, empty -> holds every response');
 await cueEl(page,'#rows p.meta:has-text("Request rules")');await sleep(1800);
 await cueEl(page,'#rows p.meta:has-text("Response rules")');await sleep(1800);
 const note=page.locator('#rows p.meta',{hasText:'Toggling a rule list keeps its stored rules'});
 if(!await note.count())throw new Error('standing toggle note missing');
 log('standing-note','page discloses toggling keeps stored rules; editing stays in the console');
 await cueEl(page,'#rows p.meta:has-text("Toggling a rule list")');await sleep(1800);

 // 2. turn response rules OFF from the page first, so the pass-through check below is not paused by a held response
 await cueEl(page,'#rows button:has-text("Turn response rules off")');
 await page.click('#rows button:has-text("Turn response rules off")');
 await page.locator('#rows p.meta:has-text("Response rules OFF")').first().waitFor();
 const roff=JSON.parse(api('GET','/api/intercept/rules/responses'));
 if(roff.active!==false)throw new Error('response list not off');
 log('response-off','response rules OFF via page button');
 await sleep(1500);

 // 3. turn request rules OFF from the page; fragment updates in place
 await cueEl(page,'#rows button:has-text("Turn request rules off")');
 await page.click('#rows button:has-text("Turn request rules off")');
 await page.locator('#rows p.meta:has-text("holds nothing while off")').first().waitFor();
 log('toggled-off','request rules OFF via page button; fragment shows holds-nothing');
 const offState=JSON.parse(api('GET','/api/intercept/rules/requests'));
 if(offState.active!==false||offState.count!==1||offState.rules[0].comment!=='film rule'||offState.rules[0].action!=='hold')throw new Error('off toggle rewrote stored rules: '+JSON.stringify(offState));
 log('rules-preserved-off','API confirms active=false, the stored rule (comment, action) intact');
 await sleep(1800);

 // 4. behavioural: both lists off -> a would-hold request passes straight through
 const r1=execSync('curl -sS -x 127.0.0.1:18095 --max-time 30 http://127.0.0.1:18101/ch21-hold-pass').toString();
 if(!r1.includes('ECHO-OF-REQUEST'))throw new Error('request not proxied while list off: '+r1.slice(0,120));
 const held0=JSON.parse(api('GET','/api/intercept'));
 if(held0.pending!==0)throw new Error('list off still held a request');
 log('passthrough-verified','/ch21-hold-pass reached the victim with the list off; nothing held');
 await sleep(1800);

 // 5. turn request rules back ON from the page; the stored rule decides again
 await cueEl(page,'#rows button:has-text("Turn request rules on")');
 await page.click('#rows button:has-text("Turn request rules on")');
 await page.locator('#rows p.meta:has-text("Request rules ON")').first().waitFor();
 const onState=JSON.parse(api('GET','/api/intercept/rules/requests'));
 if(onState.active!==true||onState.count!==1||onState.rules[0].comment!=='film rule')throw new Error('on toggle rewrote stored rules');
 log('toggled-on','request rules back ON; stored rule still intact');

 const c1=spawn('curl',['-sS','-x','127.0.0.1:18095','--max-time','60','http://127.0.0.1:18101/ch21-hold-me','-o','/tmp/ch21-resp1.txt'],{stdio:['ignore',fs.openSync('/tmp/ch21-curl1.out','w'),fs.openSync('/tmp/ch21-curl1.err','w')]});
 const c1done=new Promise(r=>c1.on('close',r));
 await sleep(1500);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(800);
 try{await page.locator('#rows td:has-text("/ch21-hold-me")').first().waitFor({timeout:8000});}
 catch(e){await page.reload({waitUntil:'domcontentloaded'});await sleep(800);await page.locator('#rows td:has-text("/ch21-hold-me")').first().waitFor();}
 log('held-after-on','with the list back on, /ch21-hold-me is held by the stored rule');
 await cueEl(page,'td:has-text("/ch21-hold-me")');await sleep(2000);
 await page.click('#rows details summary');
 await page.locator('#rows details textarea[name="raw"]').first().waitFor();
 await cueEl(page,'#rows details button:has-text("Drop")');
 await page.click('#rows details button:has-text("Drop")');
 await page.locator('text=Nothing held.').first().waitFor();
 await c1done;
 log('dropped','held request dropped; queue empty');

 // 6. response list back on from the page
 await cueEl(page,'#rows button:has-text("Turn response rules on")');
 await page.click('#rows button:has-text("Turn response rules on")');
 await page.locator('#rows p.meta:has-text("Response rules ON")').first().waitFor();
 log('response-on','response rules back ON');
 await sleep(2200);

 fs.writeFileSync('/tmp/uat_ch21_log_'+MODE+'.json',JSON.stringify(LOG,null,2));
 clearTimeout(__wd);
 await ctx.close();await browser.close();
 console.log('CH21-OK '+MODE);
})().catch(e=>{console.error('FAIL',e.message);try{fs.writeFileSync('/tmp/uat_ch21_log_'+MODE+'.json',JSON.stringify(LOG,null,2));}catch(_){}process.exit(1);});
