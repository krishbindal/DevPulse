"""Interpret public GitHub Actions run metadata without inferring coverage."""
def summarize_runs(data):
    if (not isinstance(data, dict) or type(data.get('total_count')) is not int
            or data['total_count'] < 0 or not isinstance(data.get('workflow_runs'), list)):
        raise ValueError('Unexpected Actions response.')
    runs = data['workflow_runs']
    if not runs:
        if data['total_count'] != 0:
            raise ValueError('Actions response has a count but no runs.')
        return {'status':'ok','reported_run_count':0,'latest_run':None}
    if data['total_count'] < len(runs):
        raise ValueError('Inconsistent Actions run count.')
    run = runs[0]
    if (not isinstance(run, dict) or type(run.get('id')) is not int or run['id'] <= 0
            or not isinstance(run.get('status'), str) or not isinstance(run.get('head_sha'), str)):
        raise ValueError('Unexpected Actions run.')
    fields = ('id','name','status','conclusion','event','head_sha','head_branch','created_at','updated_at')
    latest = {k:run.get(k) for k in fields}
    if any(v is not None and not isinstance(v,str) for k,v in latest.items() if k != 'id'):
        raise ValueError('Invalid Actions run field.')
    return {'status':'ok','reported_run_count':data['total_count'],'latest_run':latest}
