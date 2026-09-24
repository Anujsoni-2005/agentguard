import pytest

from agentguard.canon import canonical_json, sha256_hex

def test_canonical_json_basic():
    obj = {"b": 2, "a": 1}
    expected = b'{"a":1,"b":2}'
    assert canonical_json(obj) == expected

def test_canonical_json_nested():
    obj = {"z": {"d": 4, "c": 3}, "a": [3, 1, 2]}
    expected = b'{"a":[3,1,2],"z":{"c":3,"d":4}}'
    assert canonical_json(obj) == expected

def test_canonical_json_floats():
    obj = {"val": 1.123456789}
    # Should round to 6 decimals
    expected = b'{"val":1.123457}'
    assert canonical_json(obj) == expected

def test_sha256_hex():
    b = b"hello"
    # hash of "hello"
    assert sha256_hex(b) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
