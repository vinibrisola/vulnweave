'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const sandbox={require:n=>n==='vscode'?{}:require(n),module:{exports:{}},console,process,Buffer,setTimeout,clearTimeout};
vm.createContext(sandbox);vm.runInContext(fs.readFileSync(path.join(__dirname,'extension.js'),'utf8'),sandbox);
const risk={package:'@angular/compiler',ecosystem:'npm',currentVersion:'20.3.17',candidateVersion:'20.3.28',priority:'P1',severity:'CRITICAL',direct:true,runtime:true,advisories:[{id:'GHSA-test',aliases:['CVE-2026-0001'],summary:'Angular template vulnerability',severity:'CRITICAL'}]};
const report={project:{root:'/example/sbcweb',name:'sbcweb',ecosystem:'npm',manifest:'/example/sbcweb/package.json'},baselineId:'test-baseline',engineVersion:'0.11.0',coverageStatus:'complete',metadata:{dependencyCount:42},reconciliation:{confirmedByMultipleSources:1,artifactComponents:0},summary:{total:2,critical:1,high:1},findings:[{...risk,sources:['OSV','OSV-Scanner']},{...risk,package:'lodash',severity:'HIGH',sources:['OSV']}]};
const context={globalState:{get:()=>null}};
const execution={lockResolution:{success:false,exitCode:1,command:'npm install --package-lock-only --strict-peer-deps',output:'npm error ERESOLVE\nnpm error Found: @angular/core@20.3.17\nnpm error @angular/core@20.3.28'},build:{skipped:true,reason:'aguardando: grafo'},tests:{skipped:true,reason:'aguardando: grafo'},before:risk};
const html=sandbox.workbenchHtml({risk,report,execution},{});
assert(html.includes('DIAGNÓSTICO DO GRAFO'));assert(html.includes('Gerar nova prévia'));assert(!html.includes('data-action="apply"'));
assert(!sandbox.graphConflictHtml({success:true,output:'peer dependency'}));
assert(!sandbox.graphConflictHtml({success:false,output:'ENOTFOUND registry'}));
assert(sandbox.graphConflictHtml({success:false,output:'ERESOLVE <script>alert(1)</script>'}).includes('Conflito entre dependências'));
const dashboard=sandbox.dashboardHtml(report,context);assert(dashboard.includes('riskSearch'));assert(dashboard.includes('CVE-2026-0001'.toLowerCase()));
for (const markup of [html,dashboard]) { for(const match of markup.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]); }
if(process.env.VULNWEAVE_PREVIEW_DIR){fs.mkdirSync(process.env.VULNWEAVE_PREVIEW_DIR,{recursive:true});fs.writeFileSync(path.join(process.env.VULNWEAVE_PREVIEW_DIR,'workbench.html'),html);fs.writeFileSync(path.join(process.env.VULNWEAVE_PREVIEW_DIR,'dashboard.html'),dashboard);}
console.log('UI rendering, script syntax, conflict diagnosis and blocked apply checks passed.');
const partialReport=process.env.VULNWEAVE_TEST_REPORT ? JSON.parse(fs.readFileSync(process.env.VULNWEAVE_TEST_REPORT,'utf8')) : {...report,coverageStatus:'incomplete',warnings:['Maven <script>failed</script>']};
const partial=sandbox.dashboardHtml(partialReport,context);
assert(partial.includes('Cobertura canônica incompleta'));
assert(!partial.includes('Política atendida'));
assert(!partial.includes('Nenhuma dependência vulnerável conhecida'));
assert(partial.includes('scanStatus'));
if(partialReport.auxiliaryFindings?.length) {assert(partial.includes('SCANNER-ONLY'));assert(!partial.includes('data-action="risk"'));}
for(const m of partial.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g))new vm.Script(m[1]);
if(process.env.VULNWEAVE_PREVIEW_DIR)fs.writeFileSync(path.join(process.env.VULNWEAVE_PREVIEW_DIR,'partial.html'),partial);
console.log('Incomplete coverage, auxiliary findings and stale scan status checks passed.');
