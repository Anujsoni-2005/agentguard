"""
Canonical JSON representation — §0.4, §13.6.1
"""

import orjson

def canonical_json(data: dict) -> bytes:
    """
    Returns canonical JSON representation of the dictionary.
    Keys are sorted, and no extra whitespace is included.
    Uses orjson for performance.
    """
    return orjson.dumps(data, option=orjson.OPT_SORT_KEYS)
