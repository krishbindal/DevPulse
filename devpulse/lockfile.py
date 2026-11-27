"""Bounded npm package-lock v2/v3 inventory; no package installation or execution."""
import json
import re
from collections import Counter
from .dependencies import decode_manifest, PACKAGE

MAX_LOCKFILE_BYTES = 1_000_000
MAX_LOCKED_ENTRIES = 300
# Conservative subset: standard numeric releases only.
EXACT = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')

def summarize_lockfile(blob, expected_sha):
    data = json.loads(decode_manifest(blob,expected_sha,max_bytes=MAX_LOCKFILE_BYTES))
    if not isinstance(data,dict) or type(data.get('lockfileVersion')) is not int or data['lockfileVersion'] not in (2,3):
        raise ValueError('Only npm package-lock versions 2 and 3 are supported.')
    packages = data.get('packages')
    if not isinstance(packages,dict):
        raise ValueError('Invalid npm lockfile packages map.')
    versions = Counter()
    observed = 0
    excluded = Counter()
    for path,entry in packages.items():
        if path == '':
            continue
        observed += 1
        if not isinstance(entry,dict):
            excluded['invalid_entry'] += 1
            continue
        if entry.get('link') is True:
            excluded['link'] += 1
            continue
        # Only recognize node_modules package locations, not workspace projects.
        parts = path.split('/')
        if any(part in ('','.','..') for part in parts) or 'node_modules' not in parts:
            excluded['non_package_path'] += 1
            continue
        i = len(parts)-1-parts[::-1].index('node_modules')
        tail = parts[i+1:]
        if not (len(tail)==1 and not tail[0].startswith('@') or len(tail)==2 and tail[0].startswith('@')):
            excluded['non_package_path'] += 1
            continue
        name = entry.get('name','/'.join(tail))
        version = entry.get('version')
        if not isinstance(name,str) or len(name)>214 or not PACKAGE.fullmatch(name):
            excluded['invalid_name'] += 1
            continue
        if not isinstance(version,str) or len(version)>128 or not EXACT.fullmatch(version):
            excluded['unsupported_version'] += 1
            continue
        # Names/versions are lockfile assertions, not authenticated registry identities.
        versions[(name,version)] += 1
    rows = [{'name':n,'locked_version':v,'occurrences':count}
            for (n,v),count in sorted(versions.items())[:MAX_LOCKED_ENTRIES]]
    truncated = len(versions)>MAX_LOCKED_ENTRIES
    return {'status':'partial' if excluded or truncated else 'ok',
            'manifest':'package-lock.json','blob_sha':expected_sha,
            'lockfile_version':data['lockfileVersion'],'observed_package_records':observed,
            'recognized_records':sum(versions.values()),'unique_name_versions':len(versions),
            'excluded_records':sum(excluded.values()),'excluded_reasons':dict(sorted(excluded.items())),
            'entries':rows,'entries_truncated':truncated}
