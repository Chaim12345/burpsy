// ch20: ui2 per-held-item view/edit/forward/drop against live burpsy (web 18096, proxy 18095, echo victim 18101).
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
(async()=>{
 const __wd=setTimeout(async()=>{console.log('WATCHDOG-PARTIAL-SAVE');try{await ctx.close();}catch(e){}process.exit(2);},200000);
 const browser=await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
 const vw=MODE==='mobile'?{width:390,height:844}:{width:1280,height:800};
 const ctx=await browser.newContext({viewport:vw,recordVideo:{dir:'/tmp/vid20_'+MODE,size:vw}});
 ctx.setDefaultTimeout(25000);
 const page=await ctx.newPage();
 execSync(`curl -s -X POST ${BASE}/api/intercept/enable -H "Content-Type: application/json" -d "{\\"enabled\\":true}"`);
 execSync(`curl -s -X PUT ${BASE}/api/intercept/rules/requests -H "Content-Type: application/json" -d "{\\"active\\":true,\\"rules\\":[]}"`);
 log('armed','interception ON, unconditional request rules (armed via API: the ui2 page has no rule-list toggle)');

 // 1. a real client request gets held
 const c1=spawn('curl',['-sS','-x','127.0.0.1:18095','--max-time','90','-X','POST','http://127.0.0.1:18101/ch20-edit-test','-d','original-body','-o','/tmp/ch20-resp1.txt','-w','exit-independent-code=%{http_code}\\n'],{stdio:['ignore',fs.openSync('/tmp/ch20-curl1.out','w'),fs.openSync('/tmp/ch20-curl1.err','w')]});
 const c1done=new Promise(r=>c1.on('close',r));
 await page.goto(BASE+'/ui2/intercept',{waitUntil:'domcontentloaded'});await sleep(1500);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(800);
 await page.locator('#rows td:has-text("/ch20-edit-test")').first().waitFor();
 log('held-row','/ch20-edit-test visible in the held queue');
 await cueEl(page,'td:has-text("/ch20-edit-test")');await sleep(2200);

 // 2. open the per-item editor; it is prefilled with the held bytes
 await cueEl(page,'#rows details summary');
 await page.click('#rows details summary');
 const ta=page.locator('#rows details textarea[name="raw"]').first();
 await ta.waitFor();
 const original=await ta.inputValue();
 if(!original.includes('POST /ch20-edit-test')||!original.includes('original-body'))throw new Error('editor not prefilled with held bytes: '+original.slice(0,120));
 log('editor-prefilled','textarea carries the held request bytes');
 await cueEl(page,'#rows details textarea[name="raw"]');await sleep(1600);

 // 3. the operator edits: new path, extra header, new body, stale Content-Length left on purpose
 await ta.click();await sleep(400);
 const edited='POST /ch20-edited HTTP/1.1\r\nHost: 127.0.0.1:18101\r\nContent-Length: 13\r\nX-Operator-Edit: ui2\r\n\r\nEDITED-BODY';
 await ta.fill(edited);
 log('edited','path /ch20-edit-test -> /ch20-edited, X-Operator-Edit added, body replaced, Content-Length deliberately stale');
 await sleep(2000);
 await cueEl(page,'#rows details input[name="fix_content_length"]');await sleep(1500);
 const note=await page.locator('#rows details p.meta').first().textContent();
 if(!note.includes('CRLF')||!note.includes('base64 editor')||!note.includes('not marked user-edited'))throw new Error('disclosure note missing: '+note.slice(0,120));
 log('disclosure-shown','newline + byte-exactness + Fix Content-Length disclosures visible in the editor');
 await cueEl(page,'#rows details p.meta');await sleep(1800);

 // 4. per-item Forward with the edit
 await cueEl(page,'#rows details button:has-text("Forward")');
 await page.click('#rows details button:has-text("Forward")');
 await page.locator('text=Nothing held.').first().waitFor();
 log('queue-empty','held item resolved via per-item Forward');
 await c1done;
 const resp1=fs.readFileSync('/tmp/ch20-resp1.txt','utf8');
 if(!resp1.includes('/ch20-edited'))throw new Error('victim did not receive edited path: '+resp1.slice(0,160));
 if(!resp1.includes('EDITED-BODY'))throw new Error('victim did not receive edited body');
 if(!resp1.includes('Content-Length: 11'))throw new Error('Content-Length not recomputed: '+resp1.slice(0,200));
 if(resp1.includes('original-body'))throw new Error('original body leaked through');
 log('victim-received-edited','victim got /ch20-edited + EDITED-BODY, Content-Length recomputed 13->11, client received the response');
 await sleep(2200);

 // 5. per-item Drop on a second held request
 const c2=spawn('curl',['-sS','-x','127.0.0.1:18095','--max-time','90','http://127.0.0.1:18101/ch20-drop-test','-o','/tmp/ch20-resp2.txt','-w','exit-independent-code=%{http_code}\\n'],{stdio:['ignore',fs.openSync('/tmp/ch20-curl2.out','w'),fs.openSync('/tmp/ch20-curl2.err','w')]});
 const c2done=new Promise(r=>c2.on('close',r));
 await sleep(1500);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(800);
 try{await page.locator('#rows td:has-text("/ch20-drop-test")').first().waitFor({timeout:8000});}
 catch(e){await page.reload({waitUntil:'domcontentloaded'});await sleep(800);await page.locator('#rows td:has-text("/ch20-drop-test")').first().waitFor();}
 log('held-row-2','/ch20-drop-test held');
 await cueEl(page,'td:has-text("/ch20-drop-test")');
 await page.click('#rows details summary');
 await cueEl(page,'#rows details button:has-text("Drop")');
 await page.click('#rows details button:has-text("Drop")');
 await page.locator('text=Nothing held.').first().waitFor();
 log('dropped','per-item Drop resolved the second held item');
 await c2done;
 const resp2=fs.existsSync('/tmp/ch20-resp2.txt')?fs.readFileSync('/tmp/ch20-resp2.txt','utf8'):'';
 if(resp2.includes('ECHO-OF-REQUEST'))throw new Error('dropped request reached the victim');
 log('drop-verified','victim never saw the dropped request (client got an empty reply)');
 await sleep(1800);

 // 6. NUL-carrying (valid UTF-8) held request: no editor, guard note names NUL, untouched Forward byte-exact
 fs.writeFileSync('/tmp/ch20-nul-body.bin',Buffer.from([0x41,0x00,0x42]));
 const c3=spawn('curl',['-sS','-x','127.0.0.1:18095','--max-time','90','-X','POST','http://127.0.0.1:18101/ch20-nul-test','--data-binary','@/tmp/ch20-nul-body.bin','-o','/tmp/ch20-resp3.txt'],{stdio:['ignore',fs.openSync('/tmp/ch20-curl3.out','w'),fs.openSync('/tmp/ch20-curl3.err','w')]});
 const c3done=new Promise(r=>c3.on('close',r));
 await sleep(1500);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(800);
 try{await page.locator('#rows td:has-text("/ch20-nul-test")').first().waitFor({timeout:8000});}
 catch(e){await page.reload({waitUntil:'domcontentloaded'});await sleep(800);await page.locator('#rows td:has-text("/ch20-nul-test")').first().waitFor();}
 log('held-row-3','NUL-carrying /ch20-nul-test held');
 await cueEl(page,'td:has-text("/ch20-nul-test")');
 const nulBlock=page.locator('div.held-editor',{hasText:'not safe to edit here'}).first();
 await nulBlock.waitFor();
 if(await nulBlock.locator('textarea').count()!==0)throw new Error('NUL-carrying hold was offered an editor');
 const note3=await nulBlock.textContent();
 if(!note3.includes('NUL')||!note3.includes('base64 editor')||!note3.includes('/ch20-nul-test'))throw new Error('guard note incomplete: '+note3.slice(0,140));
 if(note3.includes('not valid UTF-8:'))throw new Error('guard note falsely claims invalid UTF-8');
 log('nul-guard-shown','no editor; note names NUL + console base64 editor + the held item; no false invalid-UTF-8 claim');
 await cueEl(page,'div.held-editor');await sleep(2000);
 await cueEl(page,'div.held-editor button:has-text("Forward")');
 await nulBlock.locator('button:has-text("Forward")').click();
 await c3done;
 const resp3=fs.readFileSync('/tmp/ch20-resp3.txt');
 if(!resp3.includes(Buffer.from([0x41,0x00,0x42])))throw new Error('NUL body corrupted on untouched forward');
 log('nul-forward-byte-exact','untouched Forward shipped A NUL B unchanged; no editor was offered');
 await page.locator('text=Nothing held.').first().waitFor();
 await sleep(2000);

 // 7. non-UTF-8 per-item Drop
 fs.writeFileSync('/tmp/ch20-bin-body.bin',Buffer.from([0xff,0xfe,0x00,0x41]));
 const c4=spawn('curl',['-sS','-x','127.0.0.1:18095','--max-time','90','-X','POST','http://127.0.0.1:18101/ch20-bin-drop','--data-binary','@/tmp/ch20-bin-body.bin','-o','/tmp/ch20-resp4.txt'],{stdio:['ignore',fs.openSync('/tmp/ch20-curl4.out','w'),fs.openSync('/tmp/ch20-curl4.err','w')]});
 const c4done=new Promise(r=>c4.on('close',r));
 await sleep(1500);
 await page.reload({waitUntil:'domcontentloaded'});await sleep(800);
 try{await page.locator('#rows td:has-text("/ch20-bin-drop")').first().waitFor({timeout:8000});}
 catch(e){await page.reload({waitUntil:'domcontentloaded'});await sleep(800);await page.locator('#rows td:has-text("/ch20-bin-drop")').first().waitFor();}
 const binBlock=page.locator('div.held-editor',{hasText:'not safe to edit here'}).first();
 await binBlock.waitFor();
 await cueEl(page,'div.held-editor button:has-text("Drop")');
 await binBlock.locator('button:has-text("Drop")').click();
 await c4done;
 const resp4=fs.existsSync('/tmp/ch20-resp4.txt')?fs.readFileSync('/tmp/ch20-resp4.txt'):Buffer.alloc(0);
 if(resp4.includes(Buffer.from('ECHO-OF-REQUEST')))throw new Error('dropped binary request reached the victim');
 log('bin-dropped','non-UTF-8 per-item Drop resolved; victim never saw it');
 await sleep(2200);

 fs.writeFileSync('/tmp/uat_ch20_log_'+MODE+'.json',JSON.stringify(LOG,null,2));
 clearTimeout(__wd);
 await ctx.close();await browser.close();
 console.log('CH20-OK '+MODE);
})().catch(e=>{console.error('FAIL',e.message);try{fs.writeFileSync('/tmp/uat_ch20_log_'+MODE+'.json',JSON.stringify(LOG,null,2));}catch(_){}process.exit(1);});
