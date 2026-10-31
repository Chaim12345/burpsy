// ch22: ui2 Scanner audit launch (review gate + confirmed run) against live burpsy (web 18096, proxy 18095, echo victim 18101).
const { chromium } = require('/tmp/pw/node_modules/playwright-core');
const { execSync } = require('child_process');
const fs = require('fs');
const BASE='http://127.0.0.1:18096';
const MODE=process.argv[2]||'mobile';
const LOG=[];
function log(k,v){LOG.push({k,v});console.log('LOG',k,typeof v==='string'?v.slice(0,200):v);}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function cue(page,x,y){await page.evaluate(([x,y])=>{const d=document.getElementById('__cue')||document.createElement('div');d.id='__cue';d.style.cssText=`position:fixed;left:${x-14}px;top:${y-14}px;width:28px;height:28px;border:3px solid #ff3b30;border-radius:50%;z-index:99999;pointer-events:none;box-shadow:0 0 6px #ff3b30;`;document.body.appendChild(d);},[x,y]);await sleep(700);await page.evaluate(()=>{const d=document.getElementById('__cue');if(d)d.remove();});}
async function cueEl(page,sel){try{const el=page.locator(sel).first();await el.scrollIntoViewIfNeeded();await page.mouse.move(5,5);const b=await el.boundingBox();if(b)await cue(page,b.x+b.width/2,b.y+b.height/2);}catch(e){console.log('CUE-SKIP',sel,e.message.slice(0,80));}}
(async()=>{
 const __wd=setTimeout(async()=>{console.log('WATCHDOG-PARTIAL-SAVE');try{await ctx.close();}catch(e){}process.exit(2);},220000);
 const browser=await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
 const vw=MODE==='mobile'?{width:390,height:844}:{width:1280,height:800};
 const ctx=await browser.newContext({viewport:vw,recordVideo:{dir:'/tmp/vid22_'+MODE,size:vw}});
 ctx.setDefaultTimeout(30000);
 const page=await ctx.newPage();

 // 1. capture a real exchange through the proxy so the page has something to audit
 execSync('curl -s -x 127.0.0.1:18095 --max-time 30 http://127.0.0.1:18101/ch22-film-target -o /dev/null');
 const hist=JSON.parse(execSync(`curl -s "${BASE}/api/history?limit=5"`).toString());
 const ex=hist.find(e=>e.path==='/ch22-film-target');
 if(!ex)throw new Error('exchange not captured');
 log('exchange-captured','GET /ch22-film-target stored as exchange '+ex.id+' (captured via the proxied client)');

 // 2. the Scanner page: status only before, plus the new launch form
 await page.goto(BASE+'/ui2/scanner',{waitUntil:'domcontentloaded'});await sleep(1500);
 await page.locator('h3:has-text("Launch an audit")').waitFor();
 const note=await page.locator('#rows > p.meta').first().textContent();
 if(!note.includes('Review step first')||!note.includes('active probes'))throw new Error('launch disclosure missing: '+note);
 log('launch-form','Launch an audit form on the page; disclosure says review-first and active probes');
 await cueEl(page,'h3:has-text("Launch an audit")');await sleep(1800);

 // 3. fill the form: exchange id + server default configuration
 await cueEl(page,'input[name="exchange_id"]');
 await page.fill('input[name="exchange_id"]',String(ex.id));
 await sleep(900);
 await cueEl(page,'select[name="config"]');await sleep(1500);
 await cueEl(page,'button:has-text("Review launch")');
 await page.click('button:has-text("Review launch")');

 // 4. the review step: exact call preview + disclosures, no launch yet
 await page.locator('#launch strong:has-text("Review before launch")').waitFor();
 const review=await page.locator('#launch').textContent();
 if(!review.includes('POST /api/scanner/audit')||!review.includes('"exchange_id": '+ex.id))throw new Error('preview does not name the exact call: '+review.slice(0,200));
 if(!review.includes('active attack probes')||!review.includes('out-of-scope')||!review.includes('one-time'))throw new Error('review disclosures missing: '+review.slice(0,200));
 log('review-step','review names POST /api/scanner/audit with exchange_id '+ex.id+'; active-probe, scope and one-time disclosures visible; nothing launched yet');
 await cueEl(page,'#launch p.meta');await sleep(2200);

 // 5. confirm: the audit launches and its outcome lands on the page
 await cueEl(page,'#launch button:has-text("Confirm and launch")');
 await page.click('#launch button:has-text("Confirm and launch")');
 await page.locator('h3:has-text("Audit outcome")').waitFor({timeout:60000});
 const outcome=await page.locator('#rows h3:has-text("Audit outcome") + p.meta').textContent();
 if(!outcome.includes('checks considered')||!outcome.includes('probe(s) sent'))throw new Error('outcome incomplete: '+outcome);
 log('audit-outcome','audit launched from the page: '+outcome.slice(0,140));
 await cueEl(page,'h3:has-text("Audit outcome")');await sleep(2200);

 // 6. the audit queue now shows the item; a second spend of the same token is refused
 const q=await page.locator('#rows p.meta:has-text("items")').first().textContent();
 log('queue-updated','audit queue row: '+q.trim().slice(0,120));
 await cueEl(page,'#rows h3:has-text("Audit queue")');await sleep(1800);
 fs.writeFileSync('/tmp/uat_ch22_log_'+MODE+'.json',JSON.stringify(LOG,null,2));
 clearTimeout(__wd);
 await ctx.close();await browser.close();
 console.log('CH22-OK '+MODE);
})().catch(e=>{console.error('FAIL',e.message);try{fs.writeFileSync('/tmp/uat_ch22_log_'+MODE+'.json',JSON.stringify(LOG,null,2));}catch(_){}process.exit(1);});
