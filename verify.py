import json
import time
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from blockchain_utils import read_ledger

# Load issuer public key
with open("issuer_pub.pem", "rb") as f:
    PUB_KEY = RSA.import_key(f.read())

def check_signature(payload, signature_b64):
    payload_str = json.dumps(payload, sort_keys=True)
    h = SHA256.new(payload_str.encode())
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(PUB_KEY).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def check_ledger(payload, blockhash):
    ledger = read_ledger()
    for block in ledger:
        if block.get("blockhash") == blockhash:
            return True
    return False

def check_expiry(token_file):
    with open(token_file, "r", encoding="utf-8") as f:
        token = json.load(f)
    payload = token["payload"]
    sig = token["signature"]
    blockhash = token["blockhash"]

    print("=== Verification Result ===")

    if check_signature(payload, sig):
        print("Signature: OK")
    else:
        print("Signature: INVALID")

    now_ts = int(time.time())
    if payload["end"] >= now_ts:
        print(f"Token valid by time (end={payload['end']} now={now_ts})")
    else:
        print(f"Token expired (end={payload['end']} now={now_ts})")

    if check_ledger(payload, blockhash):
        print(f"Ledger inclusion: OK (BlockHash={blockhash})")
    else:
        print("Ledger inclusion: NOT FOUND")

if __name__ == "__main__":
    token_file = input("Token file to verify: ").strip()
    check_expiry(token_file)
