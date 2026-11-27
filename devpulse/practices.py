"""Evidence-based engineering practices, not a numeric code-quality score."""
from pathlib import PurePosixPath

CHECKS = (
    ('readme','README','Review onboarding and reproducible usage instructions.'),
    ('license','License file','Review licensing terms; file presence alone establishes no license.'),
    ('security','Security policy','Review vulnerability reporting instructions.'),
    ('contributing','Contribution guide','Review development and contribution instructions.'),
    ('tests','Test file candidates','Run tests and measure coverage independently.'),
    ('workflows','GitHub Actions workflow files','Review workflow contents and actual runs.'),
    ('dependencies','Dependency manifest candidates','Review dependency declarations and lockfiles.'),
)

def document_kind(path):
    p=PurePosixPath(path)
    if len(p.parts)>1 and p.parts[:-1] not in (('.github',),('docs',)):
        return None
    name=p.name.lower()
    for stem,kind in (('readme','readme'),('license','license'),('licence','license'),
                      ('copying','license'),('security','security'),('contributing','contributing')):
        if name==stem or name in (stem+'.md',stem+'.txt',stem+'.rst',stem+'.adoc'):
            return kind
    return None

def assess_practices(inventory,ci):
    available=inventory.get('status') in ('ok','partial')
    complete=inventory.get('status')=='ok' and inventory.get('truncated') is False
    docs=inventory.get('practice_documents',{})
    evidence_map={'tests':'test_file_candidates','workflows':'workflow_files','dependencies':'dependency_manifests'}
    checks=[]
    for key,label,advice in CHECKS:
        evidence=(inventory.get(evidence_map[key],{}) if key in evidence_map else docs.get(key,{})) if available else {}
        count=evidence.get('observed_count')
        known=type(count) is int and count>=0
        state='observed' if known and count>0 else 'not_observed' if known and complete else 'unknown'
        checks.append({'id':key,'label':label,'state':state,
                       'observed_count':count if known else None,
                       'examples':evidence.get('examples',[])[:5] if known else [],
                       'recommendation':advice})
    latest=ci.get('latest_run') if ci.get('status')=='ok' else None
    if ci.get('status')!='ok':
        run_state='unknown'
    elif latest is None:
        run_state='not_observed'
    else:
        run_state='observed'
    checks.append({'id':'latest_run','label':'Latest GitHub Actions run','state':run_state,
                   'observed_count':1 if latest else 0 if run_state=='not_observed' else None,
                   'examples':[],'recommendation':'Review conclusion and commit; one run is not overall CI health.',
                   'run':latest})
    counts={state:sum(c['state']==state for c in checks) for state in ('observed','not_observed','unknown')}
    return {'status':'partial' if counts['unknown'] or not complete else 'ok',
            'scope':'File-name and latest-run evidence only; not verified practice effectiveness, security or code quality.',
            'tree_sha':inventory.get('tree_sha'),'tree_source':inventory.get('source'),
            'ci_source':ci.get('source'),'checks':checks,'counts':counts}
