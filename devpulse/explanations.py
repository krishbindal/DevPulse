"""Provider-neutral explanation selection; no network or free-form model text."""
import json

from .recommendations import recommend, MAX_RECOMMENDATIONS

MAX_RESPONSE_BYTES = 4096


def evidence_catalog(report):
    """Expose only locally authored labels/actions, never repository strings."""
    entries = recommend(report)['entries']
    return [
        {'id': i, 'title': entry['title'], 'action': entry['action'],
         'priority': entry['priority']}
        for i, entry in enumerate(entries)
    ]


def select_explanations(report, response=None):
    """Accept only a complete permutation of catalog IDs.

    A future opt-in provider may reorder the catalog, but cannot add claims,
    suppress findings, or supply display text. Invalid output falls back.
    """
    entries = recommend(report)['entries']
    ids = list(range(len(entries)))
    selected = ids
    mode = 'deterministic'
    if isinstance(response, str) and len(response) <= MAX_RESPONSE_BYTES:
        try:
            if len(response.encode('utf-8')) <= MAX_RESPONSE_BYTES:
                candidate = json.loads(response)
                if (type(candidate) is list
                        and len(candidate) <= MAX_RECOMMENDATIONS
                        and all(type(i) is int for i in candidate)
                        and sorted(candidate) == ids):
                    selected = candidate
                    mode = 'validated_selection'
        except (ValueError, RecursionError):
            pass
    return {'mode': mode, 'entries': [entries[i] for i in selected],
            'scope': 'Review suggestions only; selection is not a severity score.'}
