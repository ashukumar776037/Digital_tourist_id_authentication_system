# blockchain.py
"""
blockchain.py
Core functions for a file-backed JSON-line blockchain ledger.
Each line in LEDGER file is a JSON object:
{
  "block": <hex hash>,
  "prev": <hex prev hash or "" for genesis>,
  "ts": <unix epoch int>,
  "type": <"issue"|"entry"|"stay_update"|"extension"|"exit"|"revoke">,
  "payload": <dict> ,
  "sig": <base64 signature string>
}
"""
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from blockchain_utils import append_block, sha256_hex, read_ledger

LEDGER_FILE = "ledger.dat"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_ledger_lines() -> List[Dict[str,Any]]:
    p = Path(LEDGER_FILE)
    if not p.exists():
        return []
    blocks = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                blk = json.loads(line)
                blocks.append(blk)
            except Exception:
                continue
    return blocks

def get_prev_hash() -> str:
    blocks = read_ledger_lines()
    if not blocks:
        return ""
    return blocks[-1].get("block","")

def compute_raw_for_hash(prev: str, ts: int, payload: Dict, sig: str) -> bytes:
    # deterministic serialization: payload sorted keys (for stable hashing)
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    raw = f"{prev}|{ts}|{payload_json}|{sig}\n"
    return raw.encode('utf-8')

def compute_block_hash(prev: str, ts: int, payload: Dict, sig: str) -> str:
    return sha256_hex(compute_raw_for_hash(prev, ts, payload, sig))

def append_block(block_type: str, payload: Dict, sig: str) -> Dict[str,Any]:
    """
    Append a block with given type, payload and signature (base64 string).
    Returns the block dict written.
    """
    prev = get_prev_hash()
    ts = int(time.time())
    blk_hash = compute_block_hash(prev, ts, payload, sig)
    block_obj = {
        "block": blk_hash,
        "prev": prev,
        "ts": ts,
        "type": block_type,
        "payload": payload,
        "sig": sig
    }
    with Path(LEDGER_FILE).open("a", encoding="utf-8") as f:
        f.write(json.dumps(block_obj, separators=(',', ':'), sort_keys=False) + "\n")
    return block_obj

def find_block_by_hash(block_hash: str) -> Optional[Dict[str,Any]]:
    blocks = read_ledger_lines()
    for b in blocks:
        if b.get("block") == block_hash:
            return b
    return None

def find_block_for_payload_sig(payload: Dict, sig: str) -> Optional[Dict[str,Any]]:
    blocks = read_ledger_lines()
    for b in blocks:
        if b.get("payload") == payload and b.get("sig") == sig:
            return b
    return None

def find_blocks_for_kyc_hash(kyc_hash: str) -> List[Dict[str,Any]]:
    """Return all blocks containing payloads with this kyc_hash (useful to find entries)."""
    results = []
    blocks = read_ledger_lines()
    for b in blocks:
        pl = b.get("payload", {})
        if isinstance(pl, dict) and pl.get("kyc_hash") == kyc_hash:
            results.append(b)
    return results
