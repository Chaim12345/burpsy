// ch23: ui2 Logger capture controls (per-tool on/off + not-captured counters) against live burpsy (web 18096, echo victim 18101).
const { chromium } = require('/tmp/pw/node_modules/playwright-core');
const { execSync } = require('child_process');
const fs = require('fs');
const BASE='http://127.0.0.1:18096';
const MODE=process.argv[2]||'mobile';
const LOG=[];
function log(k,v){LOG.push({k,v});console.log('LOG',k,typeof v==='string'?v.slice(0,200):v);}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function b64(s){return Buffer.from(s).toString('base64');}
function repeaterSend(path){
  const raw='GET '+path+' HTTP/1.1\r\nHost: 127.0.0.1:18101\r\n\r\n';
  const out=execSync('curl -s -X POST '+BASE+'/api/repeater/send -H "Content-Type: application/json" -d \'{"target":"127.0.0.1:18101","request_base64":"'+b64(raw)+'"}\'').toString();
  return JSON.parse(out);
}
async function cue(page,x,y){await page.evaluate(([x,y])=>{const d=document.getElementById('__cue')||document.createElement('div');d.id='__cue';d.style.cssText=`position:fixed;left:${x-14}px;top:${y-14}px;width:28px;height:28px;border:3px solid #ff3b30;border-radius:50%;z-index:99999;pointer-events:none;box-shadow:0 0 6px #ff3b30;`;document.body.appendChild(d);},[x,y]);await sleep(700);await page.evaluate(()=>{const d=document.getElementById('__cue');if(d)d.remove();});}
async function cueEl(page,sel){try{const el=page.locator(sel).first();await el.scrollIntoViewIfNeeded();await page.mouse.move(5,5);const b=await el.boundingBox();if(b)await cue(page,b.x+b.width/2,b.y+b.height/2);}catch(e){console.log('CUE-SKIP',sel,e.message.slice(0,80));}}
(async()=>{
 const __wd=setTimeout(async()=>{console.log('WATCHDOG-PARTIAL-SAVE');try{await ctx.close();}catch(e){}process.exit(2);},220000);
 // deterministic start: repeater capture on, prior state cleared of ch23 rows by fresh server
 execSync('curl -s -X POST '+BASE+'/api/tools/log -H "Content-Type: application/json" -d \'{"tool":"repeater","on":true}\' >/dev/null');
 const browser=await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
 const vw=MODE==='mobile'?{width:390,height:844}:{width:1280,height:800};
 const ctx=await browser.newContext({viewport:vw,recordVideo:{dir:'/tmp/vid23_'+MODE,size:vw}});
 ctx.setDefaultTimeout(30000);
 const page=await ctx.newPage();

 // 1. the Logger page: capture axis visible, disclosure, every tool on
 await page.goto(BASE+'/ui2/logger',{waitUntil:'domcontentloaded'});await sleep(1500);
 await page.locator('#capture').waitFor();
 const cap=await page.locator('#capture').textContent();
 if(!cap.includes('deliberately not recorded'))throw new Error('off-capture disclosure missing');
 if(!cap.includes('repeater')||!cap.includes('proxy')||!cap.includes('scanner'))throw new Error('tool rows missing');
 log('capture-axis','Logger page shows per-tool capture state with the off-capture disclosure ("sent and deliberately not recorded")');
 await cueEl(page,'#capture p.meta');await sleep(2000);

 // 2. turn repeater capture OFF from the page
 await cueEl(page,'button:has-text("turn repeater off")');
 await page.click('button:has-text("turn repeater off")');
 await page.locator('button:has-text("turn repeater on")').waitFor();
 const repRow=await page.locator('#capture p:has-text("repeater")').first().textContent();
 if(!/repeater\s+off/.test(repRow))throw new Error('repeater row does not say off: '+repRow);
 log('toggled-off','repeater capture turned OFF from the page; row now says off and offers to turn it back on');
 await cueEl(page,'#capture p:has-text("repeater")');await sleep(2000);

 // 3. send a repeater request while capture is off: it goes out but is not recorded
 const r1=repeaterSend('/ping-ch23-off');
 if(r1.status!==200)throw new Error('repeater send failed: '+JSON.stringify(r1).slice(0,120));
 log('sent-while-off','repeater request GET /ping-ch23-off sent (200) while repeater capture is off');
 await sleep(600);

 // 4. reload: the row counts it as not captured, and the table has no such entry
 await page.reload({waitUntil:'domcontentloaded'});await sleep(1500);
 const repRow2=await page.locator('#capture p:has-text("repeater")').first().textContent();
 if(!repRow2.includes('not captured'))throw new Error('not-captured counter missing after off-send: '+repRow2);
 const tableText=await page.locator('#rows-body').textContent();
 if(tableText.includes('/ping-ch23-off'))throw new Error('off-capture request appeared in the log table');
 log('not-captured-counter','repeater row: '+repRow2.trim().replace(/\s+/g,' ').slice(0,110)+'; the sent request is NOT in the entries table');
 await cueEl(page,'#capture p:has-text("repeater")');await sleep(2200);

 // 5. turn repeater capture back ON from the page
 await cueEl(page,'button:has-text("turn repeater on")');
 await page.click('button:has-text("turn repeater on")');
 await page.locator('button:has-text("turn repeater off")').waitFor();
 log('toggled-on','repeater capture turned back ON from the page');
 await sleep(800);

 // 6. send another repeater request: this one IS recorded
 const r2=repeaterSend('/ping-ch23-on');
 if(r2.status!==200)throw new Error('repeater send 2 failed');
 await sleep(600);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(1500);
 const tableText2=await page.locator('#rows-body').textContent();
 if(!tableText2.includes('/ping-ch23-on'))throw new Error('on-capture request missing from the log table');
 log('recorded-when-on','GET /ping-ch23-on sent after turning capture back on appears in the entries table');
 await cueEl(page,'#rows-body tr:first-child');await sleep(2200);

 // 7. unknown actions are refused
 const bad=execSync('curl -s -o /dev/null -w "%{http_code}" -X POST '+BASE+'/ui2/logger/capture-nosuchtool-on').toString();
 if(bad!=='400')throw new Error('unknown tool action = '+bad+', want 400');
 const bad2=execSync('curl -s -o /dev/null -w "%{http_code}" -X POST '+BASE+'/ui2/logger/bogus').toString();
 if(bad2!=='400')throw new Error('unknown action = '+bad2+', want 400');
 log('refusals','POST /ui2/logger/capture-nosuchtool-on and /ui2/logger/bogus both refused with 400');
 await sleep(1200);

 fs.writeFileSync('/tmp/uat_ch23_log_'+MODE+'.json',JSON.stringify(LOG,null,2));
 clearTimeout(__wd);
 await ctx.close();await browser.close();
 console.log('CH23-OK '+MODE);
})().catch(e=>{console.error('FAIL',e.message);try{fs.writeFileSync('/tmp/uat_ch23_log_'+MODE+'.json',JSON.stringify(LOG,null,2));}catch(_){}process.exit(1);});
