# issuer.py
import json
import time
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from blockchain_utils import append_block, sha256_hex

PRIVKEY_FILE = "issuer_priv.pem"
POLICE_DB = "police_db.txt"

def load_private_key(path=PRIVKEY_FILE):
    b = Path(path).read_bytes()
    return serialization.load_pem_private_key(b, password=None)

def sign_bytes(privkey, data: bytes) -> str:
    sig = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def iso_utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def to_iso_utc_timestamp(epoch:int)->str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace('+00:00','Z')

def make_payload(name, kyc_type, kyc_hash, itinerary, emergency, start_epoch, end_epoch, extra:dict=None):
    payload = {
        "name": name,
        "kyc_type": kyc_type,
        "kyc_hash": kyc_hash,
        "itinerary": itinerary,
        "emergency": emergency,
        "start": start_epoch,
        "end": end_epoch
    }
    if extra:
        payload.update(extra)
    return payload

def save_police_summary(kyc_hash, name, start, end, block):
    with open(POLICE_DB, "a", encoding="utf-8") as f:
        f.write(f"{kyc_hash}|{name}|{start}|{end}|{block['block']}\n")

def interactive_issue():
    priv = load_private_key()
    print("=== Tourist ID Issuer (Python) ===")
    name = input("Name: ").strip()
    kyc_type = input("KYC type (AADHAAR/PASSPORT): ").strip().upper()
    kyc_raw = input("KYC identifier (raw - WILL BE HASHED): ").strip()
    itinerary = input("Itinerary (short): ").strip()
    emergency = input("Emergency contact (name:number): ").strip()
    duration_days = int(input("Visit duration (days): ").strip() or "0")

    start = int(time.time())
    end = start + duration_days * 24 * 3600

    kyc_hash = hashlib.sha256(kyc_raw.encode()).hexdigest()

    payload = make_payload(name, kyc_type, kyc_hash, itinerary, emergency, start, end)

    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    sig_b64 = sign_bytes(priv, payload_bytes)

    block = append_block("issue", payload, sig_b64)

    save_police_summary(kyc_hash, name, start, end, block)

    print("\n=== Issued Token ===")
    print("Block Hash:", block["block"])
    print("Payload JSON:", json.dumps(payload, indent=2))
    print("Signature (base64):", sig_b64)
    print("Ledger updated:", "ledger.dat")

    # Optionally ask to immediately record entry (arrival)
    do_entry = input("Record immediate ENTRY for this tourist now? (y/N): ").strip().lower()
    if do_entry == 'y':
        record_entry(kyc_hash, block["block"])

def record_entry(kyc_hash, issue_block_hash=None):
    # create entry block (records arrival time)
    priv = load_private_key()
    entry_epoch = int(time.time())
    payload = {"kyc_hash": kyc_hash, "entry": entry_epoch}
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    sig = sign_bytes(priv, payload_bytes)
    block = append_block("entry", payload, sig)
    print("Entry recorded. Block:", block["block"])
    return block

def record_exit(kyc_hash):
    priv = load_private_key()
    exit_epoch = int(time.time())
    payload = {"kyc_hash": kyc_hash, "exit": exit_epoch}
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    sig = sign_bytes(priv, payload_bytes)
    block = append_block("exit", payload, sig)
    print("Exit recorded. Block:", block["block"])
    return block

def add_extension(kyc_hash, extra_days: int):
    priv = load_private_key()
    now = int(time.time())
    # For extension, find latest issue block to get end
    from blockchain import find_blocks_for_kyc_hash
    blocks = find_blocks_for_kyc_hash(kyc_hash)
    issue_block = None
    for b in reversed(blocks):
        if b.get("type") == "issue":
            issue_block = b
            break
    if not issue_block:
        print("No original issue block found.")
        return None
    current_end = int(issue_block['payload'].get("end"))
    new_end = current_end + extra_days * 24 * 3600
    payload = {"kyc_hash": kyc_hash, "old_end": current_end, "new_end": new_end}
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    sig = sign_bytes(priv, payload_bytes)
    block = append_block("extension", payload, sig)
    print("Extension appended. Block:", block["block"])
    return block

if __name__ == "__main__":
    interactive_issue()
