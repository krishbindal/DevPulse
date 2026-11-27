"""Read bounded public npm manifest declarations without installing anything."""
import base64
import json
import re

MAX_MANIFEST_BYTES = 256_000
MAX_DECLARATIONS = 200
SECTIONS = ('dependencies','devDependencies','optionalDependencies','peerDependencies')
PACKAGE = re.compile(r'(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+\Z')
SHA = re.compile(r'[a-f0-9]{40}\Z')
# Conservative display filter: non-version specs (URLs, aliases, git, paths) are redacted.
VERSION = re.compile(r'[~^<>=vVxX*0-9.][0-9a-zA-Z.*~^<>=| +\-]{0,127}\Z')

def decode_manifest(blob, expected_sha, *, max_bytes=MAX_MANIFEST_BYTES):
    if (not isinstance(blob, dict) or blob.get('sha') != expected_sha
            or blob.get('encoding') != 'base64' or not isinstance(blob.get('content'),str)
            or type(blob.get('size')) is not int or not 0 <= blob['size'] <= max_bytes):
        raise ValueError('Unsupported or oversized manifest blob.')
    encoded = ''.join(blob['content'].split())
    if len(encoded) > 4 * ((max_bytes + 2) // 3):
        raise ValueError('Encoded npm manifest exceeded size limit.')
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) != blob['size']:
        raise ValueError('Manifest blob size mismatch.')
    return raw.decode('utf-8')

def summarize_manifest(blob, expected_sha):
    data = json.loads(decode_manifest(blob, expected_sha))
    if not isinstance(data,dict):
        raise ValueError('npm manifest must be an object.')
    counts = {}
    declarations = []
    for section in SECTIONS:
        entries = data.get(section,{})
        if not isinstance(entries,dict):
            raise ValueError('Invalid npm dependency section.')
        counts[section] = len(entries)
        for name,spec in sorted(entries.items()):
            if not PACKAGE.fullmatch(name) or len(name)>214 or not isinstance(spec,str):
                raise ValueError('Invalid npm dependency declaration.')
            display = spec if (spec == 'latest' or VERSION.fullmatch(spec)) else None
            if len(declarations)<MAX_DECLARATIONS:
                declarations.append({'name':name,'section':section,'declared_spec':display,
                                     'spec_redacted':display is None})
    total = sum(counts.values())
    return {'status':'ok','manifest':'package.json','blob_sha':expected_sha,
            'declared_counts':counts,'total_declarations':total,'entries':declarations,
            'entries_truncated':total>MAX_DECLARATIONS}
