"""Small, bounded Python AST heuristic review. Never import or execute scanned code."""
import ast
from .dependencies import decode_manifest, SHA

MAX_FILES = 5
MAX_SOURCE_BYTES = 64_000
MAX_FINDINGS = 100
RULES = {
    'PY001': 'Direct eval/exec call; review whether input is trusted.',
    'PY002': 'Explicit subprocess shell=True; review command construction.',
    'PY003': 'Direct pickle load/loads call; review data provenance.',
    'PY004': 'Bare except clause; review exception handling.',
}

def inspect_source(source):
    tree = ast.parse(source)
    matches = []
    for node in ast.walk(tree):
        rule = None
        if isinstance(node,ast.Call):
            func = node.func
            if isinstance(func,ast.Name) and func.id in ('eval','exec'):
                rule = 'PY001'
            elif isinstance(func,ast.Attribute) and isinstance(func.value,ast.Name):
                if func.value.id=='subprocess' and func.attr in ('run','Popen','call','check_call','check_output') and any(
                    k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords
                ):
                    rule = 'PY002'
                elif func.value.id=='pickle' and func.attr in ('load','loads'):
                    rule = 'PY003'
        elif isinstance(node,ast.ExceptHandler) and node.type is None:
            rule = 'PY004'
        if rule:
            matches.append({'rule':rule,'line':node.lineno,'message':RULES[rule]})
    return sorted(matches,key=lambda m:(m['line'],m['rule']))

def review_sample(inventory, fetch_blob):
    if inventory.get('status') not in ('ok','partial'):
        return {'status':'unavailable','error':'Repository tree evidence unavailable.'}
    candidates=inventory.get('python_sources',{})
    files=candidates.get('sample',[])
    observed=candidates.get('observed_count',0)
    eligible=candidates.get('eligible_count',0)
    result={'status':'ok','scope':'bounded Python AST heuristics; not a complete security audit',
            'observed_python_files':observed,'eligible_python_files':eligible,
            'selected_files':len(files),'analyzed_files':0,'failed_files':[],
            'analyzed_evidence':[],'findings':[],'observed_findings':0,
            'findings_truncated':False}
    if inventory.get('truncated') or observed>len(files):
        result['status']='partial'
    for item in files:
        sha,path=item['sha'],item['path']
        try:
            if not isinstance(sha,str) or not SHA.fullmatch(sha):
                raise ValueError('Invalid blob SHA.')
            source=decode_manifest(fetch_blob(sha),sha,max_bytes=MAX_SOURCE_BYTES)
            findings=inspect_source(source)
        except (ValueError,SyntaxError,RecursionError,OverflowError) as exc:
            result['failed_files'].append({'path':path,'blob_sha':sha,'reason':'Unreadable or unsupported Python source.'})
            result['status']='partial'
            continue
        result['analyzed_files']+=1
        result['analyzed_evidence'].append({'path':path,'blob_sha':sha})
        result['observed_findings']+=len(findings)
        remaining=MAX_FINDINGS-len(result['findings'])
        result['findings'].extend(dict(m,path=path,blob_sha=sha) for m in findings[:remaining])
    result['findings_truncated']=result['observed_findings']>MAX_FINDINGS
    if result['findings_truncated']:
        result['status']='partial'
    if files and not result['analyzed_files']:
        result['status']='unavailable'
        result['error']='No selected Python file could be analyzed.'
    elif not files and not observed and not inventory.get('truncated'):
        result['status']='not_applicable'
    return result
