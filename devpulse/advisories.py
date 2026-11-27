"""Opt-in, bounded OSV lookup for simple exact dependency declarations."""
import json
import re
from urllib.error import URLError
from urllib.request import Request, urlopen

ENDPOINT = 'https://api.osv.dev/v1/querybatch'
MAX_QUERIES = 50
PY_VERSION = re.compile(r'[0-9]+(?:\.[0-9]+)*\Z')
NPM_VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')

def lookup_advisories(report, fetch=urlopen):
    candidates = set()
    for item in report.get('python_dependencies',{}).get('entries',[]):
        v = item['declared_version']
        if v and PY_VERSION.fullmatch(v):
            candidates.add(('PyPI',item['name'],v))
    for item in report.get('npm_dependencies',{}).get('entries',[]):
        v = item['declared_spec']
        if v and NPM_VERSION.fullmatch(v):
            candidates.add(('npm',item['name'],v))
    selected = sorted(candidates)[:MAX_QUERIES]
    result = {'source':ENDPOINT,'scope':'exact declarations only; not installed dependencies',
              'eligible_unique_versions':len(candidates),'queried_versions':0,
              'entries':[],'candidate_limit_reached':len(candidates)>MAX_QUERIES}
    if not selected:
        result['status']='not_applicable'
        return result
    queries = [{'package':{'ecosystem':e,'name':n},'version':v} for e,n,v in selected]
    request = Request(ENDPOINT,data=json.dumps({'queries':queries}).encode(),
                      headers={'Content-Type':'application/json','User-Agent':'DevPulse'},method='POST')
    try:
        with fetch(request,timeout=12) as response:
            raw=response.read(1_000_001)
        if len(raw)>1_000_000:
            raise ValueError('oversized response')
        data=json.loads(raw)
        if not isinstance(data,dict) or not isinstance(data.get('results'),list) or len(data['results'])!=len(selected):
            raise ValueError('invalid response count')
        entries=[]
        partial=result['candidate_limit_reached']
        for (ecosystem,name,version), item in zip(selected,data['results']):
            if not isinstance(item,dict) or ('vulns' not in item and any(k!='next_page_token' for k in item)):
                raise ValueError('invalid result')
            vulns=item.get('vulns',[])
            if not isinstance(vulns,list) or any(not isinstance(v,dict) or not isinstance(v.get('id'),str) or not ID.fullmatch(v['id']) for v in vulns):
                raise ValueError('invalid advisory records')
            ids=sorted({v['id'] for v in vulns})
            token=item.get('next_page_token','')
            if not isinstance(token,str):
                raise ValueError('invalid pagination')
            incomplete=bool(token) or len(ids)>100
            partial=partial or incomplete
            entries.append({'ecosystem':ecosystem,'name':name,'version':version,
                            'advisory_ids':ids[:100],'observed_advisory_count':len(ids),
                            'partial':incomplete})
        result.update(status='partial' if partial else 'ok',queried_versions=len(selected),entries=entries)
    except (URLError,TimeoutError,ValueError,OSError):
        result.update(status='unavailable',error='OSV lookup unavailable or returned an invalid response.')
    return result
