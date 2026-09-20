import json
import os
import pytest

from agentguard.store.ledger import FileLedgerWriter
from agentguard.canon import canonical_json, sha256_hex

@pytest.fixture
def tmp_ledger_dir(tmp_path):
    d = tmp_path / "ledger"
    d.mkdir()
    return str(d)

@pytest.mark.asyncio
async def test_ledger_append_basic(tmp_ledger_dir):
    writer = FileLedgerWriter(tmp_ledger_dir)
    await writer.initialize()
    
    rec = await writer.append(
        run_id="run_1",
        event_type="test.event",
        actor="hub",
        action_id=None,
        payload={"msg": "hello"},
        durable=True,
    )
    
    assert rec.idx == 0
    assert rec.event_type == "test.event"
    assert rec.payload["msg"] == "hello"
    
    writer.close()
    
    # Verify file contents
    segment = os.path.join(tmp_ledger_dir, "ledger-000001.jsonl")
    assert os.path.exists(segment)
    
    with open(segment, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    assert len(lines) == 1
    loaded = json.loads(lines[0])
    
    assert loaded["idx"] == 0
    assert loaded["prev_hash"] == "0" * 64
    
    # Hash check
    without_hash = {k: v for k, v in loaded.items() if k != "hash"}
    expected_hash = sha256_hex(("0"*64).encode("ascii") + canonical_json(without_hash))
    assert loaded["hash"] == expected_hash

@pytest.mark.asyncio
async def test_ledger_recovery(tmp_ledger_dir):
    writer1 = FileLedgerWriter(tmp_ledger_dir)
    await writer1.initialize()
    
    await writer1.append(
        run_id="run_1", event_type="t1", actor="hub", action_id=None, payload={}, durable=True
    )
    await writer1.append(
        run_id="run_1", event_type="t2", actor="hub", action_id=None, payload={}, durable=True
    )
    
    writer1.close()
    
    # Deliberately corrupt the last line
    segment = os.path.join(tmp_ledger_dir, "ledger-000001.jsonl")
    with open(segment, "ab") as f:
        f.write(b'{"truncated": true\n')
        
    # Start writer2, it should recover by truncating the bad line
    writer2 = FileLedgerWriter(tmp_ledger_dir)
    await writer2.initialize()
    
    # Next idx should be 2
    assert writer2.next_idx == 2
    
    await writer2.append(
        run_id="run_1", event_type="t3", actor="hub", action_id=None, payload={}, durable=True
    )
    writer2.close()
    
    # Verify lines
    with open(segment, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 3
    
    assert json.loads(lines[0])["event_type"] == "t1"
    assert json.loads(lines[1])["event_type"] == "t2"
    assert json.loads(lines[2])["event_type"] == "t3"

@pytest.mark.asyncio
async def test_ledger_rotation(tmp_ledger_dir):
    writer = FileLedgerWriter(tmp_ledger_dir, segment_max_bytes=200) # Tiny segment size
    await writer.initialize()
    
    await writer.append(
        run_id="run_1", event_type="t1", actor="hub", action_id=None, payload={"pad": "x" * 150}, durable=True
    )
    # The first append should push size > 200, causing a rotation for the *next* append
    await writer.append(
        run_id="run_1", event_type="t2", actor="hub", action_id=None, payload={"pad": "x" * 150}, durable=True
    )
    writer.close()
    
    assert os.path.exists(os.path.join(tmp_ledger_dir, "ledger-000001.jsonl"))
    assert os.path.exists(os.path.join(tmp_ledger_dir, "ledger-000002.jsonl"))
