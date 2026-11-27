"""Conservative root requirements.txt parsing; never install or follow includes."""
import re
from .dependencies import decode_manifest, MAX_DECLARATIONS

# Intentionally narrow subset, not a complete PEP 508 parser.
NAME = r'[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,198}[A-Za-z0-9])?'
VERSION = r'[0-9][A-Za-z0-9.!+_-]{0,127}'
PIN = re.compile(r'(' + NAME + r')\s*==\s*(' + VERSION + r')\Z')
BARE = re.compile(r'(' + NAME + r')\Z')

def summarize_requirements(blob, expected_sha):
    text = decode_manifest(blob, expected_sha)
    entries = []
    counts = {'exact_pins':0,'bare_names':0,'unsupported_lines':0}
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        # Only strip whitespace-delimited comments; never expose unparsed input.
        value = re.split(r'\s+#', value, maxsplit=1)[0].strip()
        pin, bare = PIN.fullmatch(value), BARE.fullmatch(value)
        if pin:
            kind, name, version = 'exact_pins', pin[1], pin[2]
        elif bare:
            kind, name, version = 'bare_names', bare[1], None
        else:
            counts['unsupported_lines'] += 1
            continue
        counts[kind] += 1
        if len(entries)<MAX_DECLARATIONS:
            entries.append({'name':re.sub(r'[-_.]+','-',name).lower(),
                            'declared_version':version})
    total = counts['exact_pins']+counts['bare_names']
    return {'status':'partial' if counts['unsupported_lines'] or total>MAX_DECLARATIONS else 'ok',
            'manifest':'requirements.txt','blob_sha':expected_sha,'counts':counts,
            'entries':entries,'entries_truncated':total>MAX_DECLARATIONS}
