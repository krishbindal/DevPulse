"""Bounded, non-executing inspection of GitHub tree metadata."""
from collections import Counter
from pathlib import PurePosixPath

MANIFESTS = {'package.json','package-lock.json','pnpm-lock.yaml','yarn.lock',
             'pyproject.toml','requirements.txt','poetry.lock','uv.lock','Pipfile',
             'Pipfile.lock','Cargo.toml','Cargo.lock','go.mod','go.sum',
             'pom.xml','build.gradle','build.gradle.kts','Gemfile','Gemfile.lock',
             'composer.json','composer.lock','packages.lock.json','bun.lock','bun.lockb'}
MAX_EXAMPLES = 50

def summarize_tree(data):
    if (not isinstance(data, dict) or type(data.get('truncated')) is not bool
            or not isinstance(data.get('tree'), list) or not isinstance(data.get('sha'), str)):
        raise ValueError('Unexpected GitHub tree response.')
    paths = set()
    counts = Counter()
    roots = Counter()
    root_package = None
    manifests, workflows, docs, tests = [], [], [], []
    for entry in data['tree']:
        if not isinstance(entry, dict):
            raise ValueError('Invalid tree entry.')
        path, kind, mode = entry.get('path'), entry.get('type'), entry.get('mode')
        if not isinstance(path, str) or not path or path in paths or kind not in ('blob','tree','commit'):
            raise ValueError('Invalid or duplicate tree path.')
        paths.add(path)
        if kind == 'tree':
            counts['directories'] += 1
            continue
        if kind == 'commit':
            counts['submodules'] += 1
            continue
        if mode == '120000':
            counts['symlinks'] += 1
            continue
        if mode not in ('100644','100755'):
            raise ValueError('Unexpected file mode.')
        counts['files'] += 1
        p = PurePosixPath(path)
        roots[p.parts[0] if len(p.parts) > 1 else '(root)'] += 1
        name = p.name
        if path == 'package.json':
            root_package = {'sha':entry.get('sha'),'size':entry.get('size')}
        if name in MANIFESTS or (name.startswith('requirements') and name.endswith('.txt')):
            manifests.append(path)
        if len(p.parts) == 3 and p.parts[:2] == ('.github','workflows') and p.suffix in ('.yml','.yaml'):
            workflows.append(path)
        if name.lower().startswith(('readme','license','security','contributing','code_of_conduct')):
            docs.append(path)
        if any(part in ('test','tests','__tests__','spec') for part in p.parts[:-1]) or name.startswith('test_') or name.endswith(('_test.py','.test.js','.test.ts','.spec.js','.spec.ts')):
            tests.append(path)
    def evidence(items):
        return {'observed_count':len(items),'examples':sorted(items)[:MAX_EXAMPLES],
                'examples_truncated':len(items)>MAX_EXAMPLES}
    return {'status':'partial' if data['truncated'] else 'ok',
            'tree_sha':data['sha'],'truncated':data['truncated'],
            'root_package_json':root_package,
            'observed':{k:counts[k] for k in ('files','directories','symlinks','submodules')},
            'top_directories':[{'path':k,'observed_files':v} for k,v in sorted(roots.items(),key=lambda i:(-i[1],i[0]))[:20]],
            'dependency_manifests':evidence(manifests),'workflow_files':evidence(workflows),
            'documentation_files':evidence(docs),'test_file_candidates':evidence(tests)}
