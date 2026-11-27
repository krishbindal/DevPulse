import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from .inventory import summarize_tree
from .ci import summarize_runs
from .dependencies import summarize_manifest, SHA, MAX_MANIFEST_BYTES
from .python_requirements import summarize_requirements
from .advisories import lookup_advisories
from .lockfile import summarize_lockfile, MAX_LOCKFILE_BYTES

PART = re.compile(r'[A-Za-z0-9_.-]{1,100}\Z')

class ScanError(Exception):
    pass

def parse_repository(value):
    value = value.strip()
    if '://' in value:
        u = urlsplit(value)
        if u.scheme != 'https' or u.netloc.lower() != 'github.com' or u.query or u.fragment:
            raise ValueError('Use an HTTPS github.com repository URL or owner/repo.')
        value = u.path.strip('/')
    parts = value.split('/')
    if len(parts) != 2 or any(not PART.fullmatch(p) or p in ('.', '..') for p in parts):
        raise ValueError('Enter a valid owner/repo or GitHub repository URL.')
    owner, repo = parts
    repo = repo.removesuffix('.git')
    if not repo or repo in ('.', '..'):
        raise ValueError('Invalid repository name.')
    return owner, repo

def fetch_json(endpoint, fetch):
    request = Request(endpoint, headers={'Accept':'application/vnd.github+json', 'User-Agent':'DevPulse-Starter', 'X-GitHub-Api-Version':'2022-11-28'})
    try:
        with fetch(request, timeout=12) as response:
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ScanError('GitHub response exceeded the size limit.')
            data = json.loads(raw)
    except HTTPError as exc:
        if exc.code == 404:
            raise ScanError('Repository not found or not public.') from exc
        if exc.code in (403, 429):
            raise ScanError('GitHub denied access or rate limited the request.') from exc
        raise ScanError('GitHub API returned an error.') from exc
    except (URLError, TimeoutError, ValueError) as exc:
        raise ScanError('GitHub API unavailable or returned invalid data.') from exc
    return data


def scan(value, fetch=urlopen, *, include_languages=False, include_inventory=False, include_ci=False, include_dependencies=False, include_advisories=False, advisory_fetch=urlopen):
    owner, repo = parse_repository(value)
    endpoint = 'https://api.github.com/repos/' + quote(owner, safe='') + '/' + quote(repo, safe='')
    data = fetch_json(endpoint, fetch)
    if not isinstance(data, dict) or not isinstance(data.get('full_name'), str):
        raise ScanError('Unexpected GitHub response.')
    fields = ('full_name','description','stargazers_count','forks_count','open_issues_count','language','default_branch','archived','pushed_at','updated_at','html_url')
    result = {key: data.get(key) for key in fields}
    result.update(source=endpoint, scanned_at=datetime.now(timezone.utc).isoformat(), code_quality=None, security_findings=None, test_coverage=None, ci_status=None)
    if include_languages:
        source = endpoint + '/languages'
        try:
            raw = fetch_json(source, fetch)
            if not isinstance(raw, dict) or any(
                not isinstance(name, str) or type(count) is not int or count < 0
                for name, count in raw.items()
            ):
                raise ScanError('Unexpected language response.')
            total = sum(raw.values())
            entries = [
                {'name': name, 'bytes': count,
                 'percent': round(count / total * 100, 2) if total else 0}
                for name, count in sorted(raw.items(), key=lambda item: (-item[1], item[0]))
            ]
            result['languages'] = {'status': 'ok', 'source': source, 'total_bytes': total,
                                   'entries': entries}
        except ScanError as exc:
            result['languages'] = {'status': 'unavailable', 'source': source, 'error': str(exc),
                                   'total_bytes': None, 'entries': None}
    else:
        result['languages'] = {'status': 'not_analyzed', 'entries': None, 'total_bytes': None}
    result['inventory'] = {'status':'not_analyzed'}
    if include_inventory:
        branch = data.get('default_branch')
        if not isinstance(branch, str) or not branch:
            result['inventory'] = {'status':'unavailable','error':'Default branch unavailable.'}
        else:
            source = endpoint + '/git/trees/' + quote(branch, safe='') + '?recursive=1'
            try:
                result['inventory'] = summarize_tree(fetch_json(source, fetch))
                result['inventory'].update(source=source, branch=branch)
            except (ScanError, ValueError) as exc:
                result['inventory'] = {'status':'unavailable','source':source,'error':str(exc)}
    result['ci'] = {'status':'not_analyzed'}
    if include_ci:
        branch = data.get('default_branch')
        if not isinstance(branch, str) or not branch:
            result['ci'] = {'status':'unavailable','error':'Default branch unavailable.'}
        else:
            source = endpoint + '/actions/runs?branch=' + quote(branch, safe='') + '&per_page=1'
            try:
                result['ci'] = summarize_runs(fetch_json(source, fetch))
                result['ci'].update(source=source, branch=branch)
            except (ScanError, ValueError) as exc:
                result['ci'] = {'status':'unavailable','source':source,'error':str(exc)}
    result['npm_dependencies'] = {'status':'not_analyzed'}
    if include_dependencies:
        inv = result['inventory']
        package = inv.get('root_package_json')
        if inv['status'] not in ('ok','partial'):
            result['npm_dependencies'] = {'status':'unavailable','error':'Repository inventory unavailable.'}
        elif package is None:
            result['npm_dependencies'] = {'status':'not_found'} if inv['status']=='ok' else {'status':'unavailable','error':'Partial tree; root manifest presence unknown.'}
        elif not isinstance(package.get('sha'),str) or not SHA.fullmatch(package['sha']):
            result['npm_dependencies'] = {'status':'unavailable','error':'Manifest blob SHA unavailable.'}
        elif type(package.get('size')) is not int or not 0 <= package['size'] <= MAX_MANIFEST_BYTES:
            result['npm_dependencies'] = {'status':'unavailable','error':'Manifest size unknown or above limit.'}
        else:
            source = endpoint + '/git/blobs/' + package['sha']
            try:
                result['npm_dependencies'] = summarize_manifest(fetch_json(source,fetch),package['sha'])
                result['npm_dependencies']['source'] = source
            except (ScanError,ValueError) as exc:
                result['npm_dependencies'] = {'status':'unavailable','source':source,'error':'Unable to read a valid bounded npm manifest.'}
    result['python_dependencies'] = {'status':'not_analyzed'}
    if include_dependencies:
        inv = result['inventory']
        manifest = inv.get('root_requirements_txt')
        if inv['status'] not in ('ok','partial'):
            result['python_dependencies'] = {'status':'unavailable','error':'Repository inventory unavailable.'}
        elif manifest is None:
            result['python_dependencies'] = {'status':'not_found'} if inv['status']=='ok' else {'status':'unavailable','error':'Partial tree; root requirements presence unknown.'}
        elif not isinstance(manifest.get('sha'),str) or not SHA.fullmatch(manifest['sha']):
            result['python_dependencies'] = {'status':'unavailable','error':'Manifest blob SHA unavailable.'}
        elif type(manifest.get('size')) is not int or not 0 <= manifest['size'] <= MAX_MANIFEST_BYTES:
            result['python_dependencies'] = {'status':'unavailable','error':'Manifest size unknown or above limit.'}
        else:
            source = endpoint + '/git/blobs/' + manifest['sha']
            try:
                result['python_dependencies'] = summarize_requirements(fetch_json(source,fetch),manifest['sha'])
                result['python_dependencies']['source'] = source
            except (ScanError,ValueError) as exc:
                result['python_dependencies'] = {'status':'unavailable','source':source,'error':'Unable to read a valid bounded requirements manifest.'}
    result['npm_lockfile'] = {'status':'not_analyzed'}
    if include_dependencies:
        inv = result['inventory']
        manifest = inv.get('root_package_lock_json')
        if inv['status'] not in ('ok','partial'):
            result['npm_lockfile'] = {'status':'unavailable','error':'Repository inventory unavailable.'}
        elif manifest is None:
            result['npm_lockfile'] = {'status':'not_found'} if inv['status']=='ok' else {'status':'unavailable','error':'Partial tree; root lockfile presence unknown.'}
        elif not isinstance(manifest.get('sha'),str) or not SHA.fullmatch(manifest['sha']):
            result['npm_lockfile'] = {'status':'unavailable','error':'Lockfile blob SHA unavailable.'}
        elif type(manifest.get('size')) is not int or not 0 <= manifest['size'] <= MAX_LOCKFILE_BYTES:
            result['npm_lockfile'] = {'status':'unavailable','error':'Lockfile size unknown or above 1 MB limit.'}
        else:
            source = endpoint + '/git/blobs/' + manifest['sha']
            try:
                result['npm_lockfile'] = summarize_lockfile(fetch_json(source,fetch),manifest['sha'])
                result['npm_lockfile']['source'] = source
            except (ScanError,ValueError,RecursionError) as exc:
                result['npm_lockfile'] = {'status':'unavailable','source':source,'error':'Unable to read a supported bounded npm lockfile.'}
    result['advisories'] = lookup_advisories(result, advisory_fetch) if include_advisories else {'status':'not_analyzed'}
    return result
