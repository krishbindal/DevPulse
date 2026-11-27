"""Deterministic engineering recommendations grounded in observed scan evidence."""
MAX_RECOMMENDATIONS = 40
PRACTICE_ACTIONS = {
    'readme': 'Check for onboarding documentation and add a README if needed.',
    'license': 'Confirm the intended licensing terms and document them if appropriate.',
    'security': 'Document how security issues should be reported.',
    'contributing': 'Document development and contribution steps if appropriate.',
    'tests': 'Locate existing tests or add a focused regression suite.',
    'workflows': 'Confirm the CI provider and add a reproducible test workflow if needed.',
    'dependencies': 'Check whether dependencies require an explicit manifest.',
    'latest_run': 'Check whether automated workflows have been configured and run.',
}
STATIC_ACTIONS = {
    'PY001': 'Review dynamic execution and replace it with explicit parsing where feasible.',
    'PY002': 'Review shell command construction and prefer an argument list with shell disabled.',
    'PY003': 'Verify deserialization inputs are trusted; consider a safer format.',
    'PY004': 'Review the bare exception handler and catch appropriate specific exceptions.',
}
SECTION_LABELS = {
    'languages':'Language metadata', 'inventory':'Tree inventory', 'ci':'CI metadata',
    'npm_dependencies':'npm declarations', 'python_dependencies':'Python requirements',
    'npm_lockfile':'npm lockfile', 'advisories':'Advisory lookup', 'static_python':'Static Python review',
    'practices':'Engineering practices',
}

def recommend(report):
    items=[]
    def add(kind,priority,title,action,evidence):
        items.append({'kind':kind,'priority':priority,'title':title,'action':action,'evidence':evidence})
    advisory=report.get('advisories',{})
    if advisory.get('status') in ('ok','partial'):
        for entry in advisory.get('entries',[]):
            if entry.get('advisory_ids'):
                add('advisory','review_first','Review reported dependency advisories',
                    'Check the advisory details, actual installed version and applicability before selecting a fix.',
                    {'section':'advisories','ecosystem':entry['ecosystem'],'name':entry['name'],
                     'version':entry['version'],'advisory_ids':entry['advisory_ids'],
                     'version_evidence':entry.get('evidence',[]),'source':advisory.get('source')})
    ci=report.get('ci',{})
    latest=ci.get('latest_run') if ci.get('status')=='ok' else None
    if latest and latest.get('status')=='completed' and latest.get('conclusion') in ('failure','timed_out','startup_failure','action_required'):
        add('ci','review_first','Investigate latest unsuccessful workflow',
            'Inspect the run logs and reproduce the failure at its recorded commit.',
            {'section':'ci','run_id':latest['id'],'head_sha':latest['head_sha'],
             'conclusion':latest['conclusion'],'source':ci.get('source')})
    static=report.get('static_python',{})
    if static.get('status') in ('ok','partial'):
        for finding in static.get('findings',[]):
            rule=finding.get('rule')
            if rule in STATIC_ACTIONS:
                add('static','review','Review Python heuristic match',STATIC_ACTIONS[rule],
                    {'section':'static_python','rule':rule,'path':finding['path'],
                     'line':finding['line'],'blob_sha':finding['blob_sha']})
    practices=report.get('practices',{})
    if practices.get('status') in ('ok','partial'):
        for check in practices.get('checks',[]):
            key=check.get('id')
            if check.get('state')=='not_observed' and key in PRACTICE_ACTIONS:
                add('practice','review','Check unobserved engineering practice',PRACTICE_ACTIONS[key],
                    {'section':'practices','check_id':key,'state':'not_observed',
                     'tree_sha':practices.get('tree_sha'),'ci_source':practices.get('ci_source') if key=='latest_run' else None})
    for key,label in SECTION_LABELS.items():
        status=report.get(key,{}).get('status')
        if status in ('partial','unavailable'):
            add('coverage','verify','Verify incomplete '+label.lower(),
                'Review the recorded coverage limits or unavailable data; do not infer a clean result.',
                {'section':key,'status':status})
    for key in ('advisories','static_python'):
        if report.get(key,{}).get('status')=='not_analyzed':
            add('coverage','verify','Optional '+SECTION_LABELS[key].lower()+' not requested',
                'Enable this optional analysis if relevant and acceptable under its stated data-sharing scope.',
                {'section':key,'status':'not_analyzed'})
    priority={'review_first':0,'review':1,'verify':2}
    items.sort(key=lambda item:priority[item['priority']])
    return {'status':'ok','method':'deterministic-evidence-rules-v1',
            'scope':'Suggested review order, not severity, exploitability or a code-quality score. No AI service used.',
            'observed_recommendations':len(items),'entries_truncated':len(items)>MAX_RECOMMENDATIONS,
            'entries':items[:MAX_RECOMMENDATIONS]}
