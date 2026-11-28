const $=id=>document.getElementById(id);let lastReport=null;
function renderAdvisories(a){
 $('advisories-entries').replaceChildren();$('advisories-coverage').replaceChildren();
 $('advisories-source').textContent=a?.source?'Source: '+a.source:'';
 const usable=a?.status==='ok'||a?.status==='partial';
 $('advisories-status').textContent=usable?'Queried '+a.queried_versions+' supported exact versions. '+(a.status==='partial'?'Partial results. ':'')+'Not an installed dependency audit or proof of security.':a?.status==='not_applicable'?'No supported exact versions available to query.':a?.error||'Not analyzed (opt in to enable).';
 if(a?.coverage)for(const [ecosystem,c] of Object.entries(a.coverage)){const li=document.createElement('li');li.textContent=ecosystem+': manifest '+c.manifest_status+' · '+c.observed_declarations+' observed declarations · '+c.ineligible_observed_declarations+' not eligible for lookup · '+c.unsupported_lines+' unsupported lines'+(c.entries_truncated?' · declaration list truncated':'');$('advisories-coverage').append(li)}
 if(a?.lockfile_coverage){const c=a.lockfile_coverage;const li=document.createElement('li');li.textContent='npm lockfile: '+c.status+' · '+c.observed_unique_pairs+' observed pairs · '+c.excluded_records+' excluded records · '+c.ineligible_pairs+' ineligible pairs'+(c.entries_truncated?' · list truncated':'');$('advisories-coverage').append(li)}
 if(usable)for(const entry of a.entries){const li=document.createElement('li');li.textContent=entry.ecosystem+' · '+entry.name+' '+entry.version+' · '+entry.evidence.join(' + ')+' · '+(entry.advisory_ids.length?entry.advisory_ids.join(', '):'No advisories returned')+(entry.partial?' (partial)':'');$('advisories-entries').append(li)}
}
function renderPython(py){
 $('python-entries').replaceChildren();
 $('python-source').textContent=py?.source?'Source: '+py.source:'';
 const usable=py?.status==='ok'||py?.status==='partial';
 $('python-status').textContent=usable?py.counts.exact_pins+' exact pin lines · '+py.counts.bare_names+' bare name lines · '+py.counts.unsupported_lines+' unsupported lines. Declarations only; not installed versions.'+(py.status==='partial'?' Partial analysis.':''):py?.status==='not_found'?'No regular root requirements.txt found in the complete tree.':py?.error||'Not analyzed';
 if(usable)for(const entry of py.entries){const li=document.createElement('li');li.textContent=entry.name+' · '+(entry.declared_version??'No declared version');$('python-entries').append(li)}
}
function renderLock(lock){
 $('lock-entries').replaceChildren();$('lock-source').textContent=lock?.source?'Source: '+lock.source:'';
 const usable=lock?.status==='ok'||lock?.status==='partial';
 $('lock-status').textContent=usable?'Lockfile v'+lock.lockfile_version+' · '+lock.recognized_records+' recognized records · '+lock.unique_name_versions+' distinct name/version pairs · '+lock.excluded_records+' excluded records. '+(lock.entries_truncated?'List capped at 300 pairs. ':'')+(lock.status==='partial'?'Partial inventory. ':'')+'Locked versions are not installed versions; supported pairs are eligible for opt-in OSV lookup.':lock?.status==='not_found'?'No regular root package-lock.json found in the complete tree.':lock?.error||'Not analyzed';
 if(usable)for(const entry of lock.entries){const li=document.createElement('li');li.textContent=entry.name+' · '+entry.locked_version+' · '+entry.occurrences+' lockfile record(s)';$('lock-entries').append(li)}
}
function renderNpm(npm){
 $('npm-entries').replaceChildren();
 $('npm-source').textContent=npm?.source?'Source: '+npm.source:'';
 $('npm-status').textContent=npm?.status==='ok'?npm.total_declarations+' declared entries across npm dependency sections. Versions are declarations, not installed versions or vulnerability findings.'+(npm.entries_truncated?' Showing first 200.':''):npm?.status==='not_found'?'No regular root package.json found in the complete tree.':npm?.error||'Not analyzed';
 if(npm?.status==='ok')for(const entry of npm.entries){const li=document.createElement('li');li.textContent=entry.name+' · '+entry.section+' · '+(entry.declared_spec??'Non-version spec omitted');$('npm-entries').append(li)}
}
function renderCI(ci){
 const latest=ci?.latest_run;
 $('ci-status').textContent=ci?.status==='ok'?(latest?(latest.name||'Workflow')+' · '+latest.status+(latest.conclusion?' · '+latest.conclusion:''):'No runs reported for this branch'):(ci?.error||'Not analyzed');
 $('ci-detail').textContent=latest?'Event: '+(latest.event||'Unavailable')+' · Commit: '+latest.head_sha+' · Created: '+(latest.created_at||'Unavailable')+' · Runs reported: '+ci.reported_run_count+'. This is not an aggregate CI health or test coverage result.':'';
 $('ci-source').textContent=ci?.source?'Source: '+ci.source:'';
}
function renderStatic(review){
 $('static-findings').replaceChildren();
 $('static-source').textContent=review?.tree_sha?'Tree: '+review.tree_sha+' · Source: '+review.source:'';
 const usable=review?.status==='ok'||review?.status==='partial';
 $('static-status').textContent=usable?review.analyzed_files+' of '+review.observed_python_files+' observed Python files analyzed · '+review.observed_findings+' heuristic matches. '+(review.status==='partial'?'Partial review. ':'')+(review.findings_truncated?'Finding list capped. ':'')+'Not a confirmed vulnerability assessment.':review?.status==='not_applicable'?'No regular Python files observed in complete tree.':review?.error||'Not analyzed (opt in to enable).';
 if(usable)for(const finding of review.findings){const li=document.createElement('li');li.textContent=finding.rule+' · '+finding.path+':'+finding.line+' · '+finding.message;$('static-findings').append(li)}
}
function renderPractices(practices){
 $('practice-checks').replaceChildren();
 $('practice-source').textContent=practices?.tree_sha?'Tree: '+practices.tree_sha:'';
 const usable=practices?.status==='ok'||practices?.status==='partial';
 $('practices-status').textContent=usable?practices.counts.observed+' observed · '+practices.counts.not_observed+' not observed · '+practices.counts.unknown+' unknown. '+practices.scope:'Not analyzed';
 if(usable)for(const check of practices.checks){const li=document.createElement('li');const title=document.createElement('strong');title.textContent=check.label+' — '+check.state.replace('_',' ');li.append(title,document.createTextNode(' · '+check.recommendation));if(check.examples.length){const p=document.createElement('p');p.textContent=check.examples.join(', ');li.append(p)}if(check.run){const p=document.createElement('p');p.textContent='Latest run: '+check.run.status+' · '+(check.run.conclusion||'no conclusion')+' · '+check.run.head_sha;li.append(p)}$('practice-checks').append(li)}
}
function renderRecommendations(result){
 $('recommendations-list').replaceChildren();
 $('recommendations-status').textContent=result?.status==='ok'?result.observed_recommendations+' suggested review tasks. '+(result.entries_truncated?'Showing first 40. ':'')+result.scope:'Not analyzed';
 if(result?.status!=='ok')return;
 if(!result.entries.length){const li=document.createElement('li');li.textContent='No tasks generated by the supported rules. This is not proof that the repository is healthy.';$('recommendations-list').append(li)}
 for(const item of result.entries){const li=document.createElement('li');const heading=document.createElement('strong');heading.textContent=item.title+' · '+item.priority.replaceAll('_',' ');const action=document.createElement('p');action.textContent=item.action;const detail=document.createElement('p');detail.textContent='Evidence: '+Object.entries(item.evidence).filter(([,v])=>v!==null&&v!==undefined).map(([k,v])=>k.replaceAll('_',' ')+': '+(Array.isArray(v)?v.join(', '):v)).join(' · ');li.append(heading,action,detail);$('recommendations-list').append(li)}
}
function renderInventory(inv){
 $('inventory-counts').replaceChildren();$('inventory-evidence').replaceChildren();
 $('inventory-source').textContent=inv?.source?'Source: '+inv.source+(inv.tree_sha?' · Tree '+inv.tree_sha:''):'';
 const usable=inv?.status==='ok'||inv?.status==='partial';
 $('inventory-status').textContent=usable?(inv.truncated?'Partial inventory: counts are lower bounds.':'Complete returned tree inventory.')+' File-name evidence only; no code execution or dependency/version audit.':inv?.error||'Not analyzed';
 if(!usable)return;
 for(const [name,value] of Object.entries(inv.observed)){const tile=document.createElement('div');tile.className='tile';const dt=document.createElement('dt');dt.textContent=name;const dd=document.createElement('dd');dd.textContent=value;tile.append(dt,dd);$('inventory-counts').append(tile)}
 for(const [label,key] of [['Dependency manifests','dependency_manifests'],['GitHub Actions workflow files','workflow_files'],['Documentation candidates','documentation_files'],['Test file candidates','test_file_candidates']]){const evidence=inv[key];const h=document.createElement('h4');h.textContent=label+' · '+evidence.observed_count+' observed';const ul=document.createElement('ul');for(const path of evidence.examples){const li=document.createElement('li');li.textContent=path;ul.append(li)}if(evidence.examples_truncated){const li=document.createElement('li');li.textContent='Additional paths omitted from display.';ul.append(li)}$('inventory-evidence').append(h,ul)}
}
$('download').addEventListener('click',()=>{if(!lastReport)return;const u=URL.createObjectURL(new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=u;a.download='devpulse-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)});
const fields=[['Stars','stargazers_count'],['Forks','forks_count'],['Open issues & PRs','open_issues_count'],['Primary language','language'],['Default branch','default_branch'],['Last push','pushed_at'],['Code quality','code_quality'],['Security findings','security_findings'],['Test coverage','test_coverage'],['Overall CI health','ci_status']];$('form').addEventListener('submit',async e=>{e.preventDefault();$('submit').disabled=true;$('results').hidden=true;lastReport=null;$('status').textContent='Fetching public GitHub metadata…';try{const r=await fetch('/api/scan?repo='+encodeURIComponent($('repo').value)+($('advisories-opt').checked?'&advisories=1':'')+($('static-opt').checked?'&static=1':''));const data=await r.json();if(!r.ok)throw new Error(data.error||'Scan failed');$('name').textContent=data.full_name;$('description').textContent=data.description||'No description provided.';$('metrics').replaceChildren();for(const [label,key] of fields){const tile=document.createElement('div');tile.className='tile';const dt=document.createElement('dt');dt.textContent=label;const dd=document.createElement('dd');dd.textContent=data[key]??(fields.slice(6).some(x=>x[1]===key)?'Not analyzed':'Unavailable');tile.append(dt,dd);$('metrics').append(tile)}const lang=data.languages;$('languages').replaceChildren();if(lang?.status==='ok'&&lang.entries.length){for(const entry of lang.entries){const li=document.createElement('li');const label=document.createElement('span');label.textContent=entry.name+' · '+entry.percent+'% ('+entry.bytes.toLocaleString()+' bytes)';const meter=document.createElement('meter');meter.min=0;meter.max=100;meter.value=entry.percent;meter.setAttribute('aria-label',entry.name+' share of reported language bytes');li.append(label,meter);$('languages').append(li)}}else{const li=document.createElement('li');li.textContent=lang?.status==='ok'?'No languages reported':lang?.error||'Not analyzed';$('languages').append(li)}$('language-source').textContent=lang?.source?'Source: '+lang.source:'';$('provenance').textContent='Source: '+data.source+' · Scanned at '+data.scanned_at;renderInventory(data.inventory);renderCI(data.ci);renderNpm(data.npm_dependencies);renderPython(data.python_dependencies);renderAdvisories(data.advisories);renderLock(data.npm_lockfile);renderStatic(data.static_python);renderPractices(data.practices);renderRecommendations(data.recommendations);lastReport=data;$('results').hidden=false;$('name').focus();$('status').textContent=(r.headers.get('X-DevPulse-Cache')==='HIT'?'Cached report (original scan time shown). ':'Fresh scan. ')+'See each analysis section for availability.'}catch(err){$('status').textContent=err.message||'Request failed.'}finally{$('submit').disabled=false}});

const comparisonLimit=2*1024*1024;
async function readComparisonFile(file){
 if(!file||file.size>comparisonLimit)throw new Error('Choose a JSON report no larger than 2 MiB.');
 const report=JSON.parse(await file.text());
 if(!report||typeof report!=='object'||Array.isArray(report)||typeof report.full_name!=='string'||!report.full_name.trim())throw new Error('Expected a report with a repository name.');
 return report;
}
const comparisonCount=(r,k)=>Number.isSafeInteger(r[k])&&r[k]>=0?r[k]:null;
const comparisonStatus=(r,k)=>['ok','partial','unavailable','not_analyzed','not_found','not_applicable'].includes(r[k]?.status)?r[k].status:'unknown';
const comparisonText=v=>typeof v==='string'?v:'Unknown';
$('compare-form').addEventListener('submit',async e=>{
 e.preventDefault();$('compare-submit').disabled=true;$('compare-result').hidden=true;$('compare-rows').replaceChildren();$('compare-status').textContent='Reading local files…';
 try{
 const [a,b]=await Promise.all([readComparisonFile($('compare-left').files[0]),readComparisonFile($('compare-right').files[0])]);
 const add=(label,left,right,difference)=>{const tr=document.createElement('tr');for(const [i,value] of [label,left,right,difference].entries()){const cell=document.createElement(i===0?'th':'td');if(i===0)cell.scope='row';cell.textContent=value??'Unknown';tr.append(cell)}$('compare-rows').append(tr)};
 for(const [label,key] of fields.slice(0,3)){const left=comparisonCount(a,key),right=comparisonCount(b,key);add(label,left,right,left===null||right===null?null:right-left)}
 for(const key of ['languages','inventory','ci','npm_dependencies','python_dependencies','npm_lockfile','advisories','static_python','practices'])add(key.replaceAll('_',' '),comparisonStatus(a,key),comparisonStatus(b,key),'Not applicable');
 $('compare-provenance').textContent='Left: '+a.full_name+' · '+comparisonText(a.scanned_at)+' · '+comparisonText(a.source)+' | Right: '+b.full_name+' · '+comparisonText(b.scanned_at)+' · '+comparisonText(b.source);
 $('compare-result').hidden=false;$('compare-status').textContent='Comparison ready. Separate snapshots; no security ranking.';
 }catch(err){$('compare-status').textContent=err instanceof SyntaxError?'Invalid JSON report.':err.message||'Cannot read reports.'}finally{$('compare-submit').disabled=false}
});
