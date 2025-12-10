import json
import time
import base64
from blockchain_utils import read_ledger, write_ledger, append_block
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Load issuer private key
with open("issuer_priv.pem", "rb") as f:
    PRIV_KEY = RSA.import_key(f.read())

def sign_payload(payload: dict):
    payload_str = json.dumps(payload, sort_keys=True)
    h = SHA256.new(payload_str.encode())
    signature = pkcs1_15.new(PRIV_KEY).sign(h)
    return base64.b64encode(signature).decode()

def update_stay(tid, days_change):
    ledger = read_ledger()
    found = None
    for block in ledger[::-1]:
        payload = block["payload"]
        if payload.get("tourist_id") == tid:
            found = payload
            break
    if not found:
        print(f"[!] Tourist ID {tid} not found in ledger.")
        return

    old_end = found["end"]
    new_end = old_end + days_change*86400
    found["end"] = new_end

    sig_b64 = sign_payload(found)
    block_hash = append_block("update_stay", found, sig_b64)
    print(f"[+] Stay updated: {tid}, new end={new_end}")
    print(f"[+] Ledger block hash: {block_hash}")

if __name__ == "__main__":
    tid = input("Tourist ID to update: ").strip()
    days = int(input("Days to add/subtract (+/-): ").strip())
    update_stay(tid, days)
