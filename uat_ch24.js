// ch24: ui2 Logger capture-filter editor against live burpsy (web 18096, echo victim 18101).
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
  return JSON.parse(execSync('curl -s -X POST '+BASE+'/api/repeater/send -H "Content-Type: application/json" -d \'{"target":"127.0.0.1:18101","request_base64":"'+b64(raw)+'"}\'').toString());
}
async function cue(page,x,y){await page.evaluate(([x,y])=>{const d=document.getElementById('__cue')||document.createElement('div');d.id='__cue';d.style.cssText=`position:fixed;left:${x-14}px;top:${y-14}px;width:28px;height:28px;border:3px solid #ff3b30;border-radius:50%;z-index:99999;pointer-events:none;box-shadow:0 0 6px #ff3b30;`;document.body.appendChild(d);},[x,y]);await sleep(700);await page.evaluate(()=>{const d=document.getElementById('__cue');if(d)d.remove();});}
async function cueEl(page,sel){try{const el=page.locator(sel).first();await el.scrollIntoViewIfNeeded();await page.mouse.move(5,5);const b=await el.boundingBox();if(b)await cue(page,b.x+b.width/2,b.y+b.height/2);}catch(e){console.log('CUE-SKIP',sel,e.message.slice(0,80));}}
(async()=>{
 const __wd=setTimeout(async()=>{console.log('WATCHDOG-PARTIAL-SAVE');try{await ctx.close();}catch(e){}process.exit(2);},220000);
 // deterministic start: no capture filter
 execSync('curl -s -X POST '+BASE+'/ui2/logger/filter-clear -d "search=" >/dev/null');
 const browser=await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
 const vw=MODE==='mobile'?{width:390,height:844}:{width:1280,height:800};
 const ctx=await browser.newContext({viewport:vw,recordVideo:{dir:'/tmp/vid24_'+MODE,size:vw}});
 ctx.setDefaultTimeout(30000);
 const page=await ctx.newPage();

 // 1. the Logger page: filter section with disclosure and no-filter state
 await page.goto(BASE+'/ui2/logger',{waitUntil:'domcontentloaded'});await sleep(1500);
 await page.locator('#filter').waitFor();
 const f0=await page.locator('#filter').textContent();
 if(!f0.includes('decides what gets recorded'))throw new Error('filter disclosure missing');
 if(!f0.includes('no capture filter'))throw new Error('no-filter state missing');
 log('filter-section','Logger page shows the capture-filter editor with the recording disclosure; state: no capture filter');
 await cueEl(page,'#filter p.meta');await sleep(2000);

 // 2. set a filter from the page: term ch24keep, status 2xx
 await cueEl(page,'input[name="term"]');
 await page.fill('input[name="term"]','ch24keep');
 await sleep(700);
 await cueEl(page,'input[name="status"][value="2"]');
 await page.check('input[name="status"][value="2"]');
 await sleep(700);
 await cueEl(page,'button:has-text("apply capture filter")');
 await page.click('button:has-text("apply capture filter")');
 await page.locator('#filter p.meta:has-text("ch24keep")').waitFor();
 const f1=await page.locator('#filter').textContent();
 if(!f1.includes('2xx')||!f1.includes('ch24keep'))throw new Error('filter echo missing: '+f1.slice(0,160));
 log('filter-set','capture filter applied from the page: status 2xx + term ch24keep, echoed as now-in-force');
 await cueEl(page,'#filter p.meta:has-text("ch24keep")');await sleep(2200);

 // 3. traffic: a matching row is recorded; non-matching rows are refused and counted
 const r1=repeaterSend('/ch24keep-this');
 if(r1.status!==200)throw new Error('send 1 failed');
 const r2=repeaterSend('/ch24skip-this');
 if(r2.status!==200)throw new Error('send 2 failed');
 await sleep(600);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(1500);
 const table=await page.locator('#rows-body').textContent();
 if(!table.includes('/ch24keep-this'))throw new Error('matching row not recorded');
 if(table.includes('/ch24skip-this'))throw new Error('refused row appeared in the table');
 const f2=await page.locator('#filter').textContent();
 if(!f2.includes('filtered so far'))throw new Error('filtered counter missing after refused rows');
 log('selective-recording','/ch24keep-this recorded in the table; /ch24skip-this sent (200) but NOT recorded; filtered counter visible: '+f2.match(/\d+ filtered so far/));
 await cueEl(page,'#rows-body tr:first-child');await sleep(2200);

 // 4. an invalid filter is refused with its reason; the old filter survives
 await page.fill('input[name="term"]','[bad');
 await page.check('input[name="regex"]');
 await sleep(500);
 await cueEl(page,'button:has-text("apply capture filter")');
 await page.click('button:has-text("apply capture filter")');
 await page.locator('#filter strong:has-text("Filter not applied")').waitFor();
 const f3=await page.locator('#filter').textContent();
 if(!f3.includes('ch24keep'))throw new Error('previous filter lost after refused change');
 log('invalid-refused','invalid regex refused: page says Filter not applied with the reason; the ch24keep filter survives');
 await cueEl(page,'#filter strong:has-text("Filter not applied")');await sleep(2200);

 // 5. clear from the page: everything recorded again
 await cueEl(page,'button:has-text("clear capture filter")');
 await page.click('button:has-text("clear capture filter")');
 await page.locator('#filter p.meta:has-text("no capture filter")').waitFor();
 const r3=repeaterSend('/ch24-after-clear');
 if(r3.status!==200)throw new Error('send 3 failed');
 await sleep(600);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(1500);
 const table2=await page.locator('#rows-body').textContent();
 if(!table2.includes('/ch24-after-clear'))throw new Error('row after clear not recorded');
 log('cleared','filter cleared from the page; /ch24-after-clear recorded again');
 await cueEl(page,'#filter p.meta:has-text("no capture filter")');await sleep(2000);

 fs.writeFileSync('/tmp/uat_ch24_log_'+MODE+'.json',JSON.stringify(LOG,null,2));
 clearTimeout(__wd);
 await ctx.close();await browser.close();
 console.log('CH24-OK '+MODE);
})().catch(e=>{console.error('FAIL',e.message);try{fs.writeFileSync('/tmp/uat_ch24_log_'+MODE+'.json',JSON.stringify(LOG,null,2));}catch(_){}process.exit(1);});
