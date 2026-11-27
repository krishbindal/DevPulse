"""Live checks against fixed public fixtures; no tokens or repository code execution."""
import json
import sys
from devpulse.scanner import scan, ScanError
from devpulse.advisories import lookup_advisories

def verify():
    # Small long-lived public fixture. No mutable star counts or branch name assumptions.
    report=scan('octocat/Hello-World',include_languages=True,include_inventory=True)
    if report['full_name'].lower()!='octocat/hello-world':
        raise RuntimeError('GitHub returned an unexpected repository identity.')
    if report['languages']['status']!='ok':
        raise RuntimeError('GitHub languages unavailable: '+str(report['languages'].get('error','unknown')))
    inv=report['inventory']
    if inv['status']!='ok' or inv['observed']['files']<1 or not inv.get('tree_sha'):
        raise RuntimeError('GitHub tree did not return complete nonempty evidence.')
    print(json.dumps({'check':'github_public_scan','status':'passed','repository':report['full_name'],
                      'tree_sha':inv['tree_sha'],'files':inv['observed']['files'],
                      'language_count':len(report['languages']['entries'])}),flush=True)
    # Public, intentionally old version with a documented historical advisory.
    # No package is installed; the only external data is the name/version.
    fixture={'python_dependencies':{'status':'not_found'},
             'npm_dependencies':{'status':'ok','entries':[{'name':'lodash','declared_spec':'4.17.20'}]},
             'npm_lockfile':{'status':'not_found'}}
    result=lookup_advisories(fixture)
    if result['status'] not in ('ok','partial') or result['queried_versions']!=1:
        raise RuntimeError('OSV query unavailable or incomplete: '+str(result.get('error','unknown')))
    entry=result['entries'][0]
    if entry['name']!='lodash' or entry['version']!='4.17.20' or not entry['advisory_ids']:
        raise RuntimeError('OSV returned no advisory evidence for the known historical fixture.')
    print(json.dumps({'check':'osv_public_query','status':'passed','package':entry['name'],
                      'version':entry['version'],'observed_advisory_ids':entry['advisory_ids'],
                      'partial':entry['partial']}),flush=True)

if __name__=='__main__':
    try:
        verify()
    except (ScanError,RuntimeError) as exc:
        print('Live smoke failed: '+str(exc),file=sys.stderr)
        sys.exit(1)
