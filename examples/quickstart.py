#!/usr/bin/env python3
"""Discover an Omni terminal (or the emulator), pair with the PIN it shows, pay 150.00 MAD, reverse it.

    python3 examples/quickstart.py [HOST]     # no HOST: broadcast discovery on UDP 8481
"""
import hashlib, hmac, json, secrets, socket, sys, time, urllib.error, urllib.request

def discover(host=None):                                  # UDP probe; reply = {"device","model","version","hmac"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.settimeout(3)
        s.sendto(b"OMNI-DISC:" + secrets.token_hex(8).encode(), (host or "255.255.255.255", 8481))
        reply, addr = s.recvfrom(1024)
    return addr[0], json.loads(reply)

def call(method, path, body=None, token=None):            # token = (tokenId, tokenHmac hex) for signed routes
    raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else b""
    headers = {"Content-Type": "application/json"}
    if token:                                              # sig = HMAC(bytes(tokenHmac), "tokenId:ts:METHOD:path:sha256(body)")
        ts = str(int(time.time()))
        msg = f"{token[0]}:{ts}:{method}:{path}:{hashlib.sha256(raw).hexdigest()}"
        sig = hmac.new(bytes.fromhex(token[1]), msg.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = f"OMNI-TOKEN tokenId={token[0]},ts={ts},sig={sig}"
    req = urllib.request.Request(f"http://{ip}:8080{path}", data=raw or None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r: return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e: sys.exit(f"{method} {path} → HTTP {e.code} {e.read().decode()}")

ip, ident = discover(sys.argv[1] if len(sys.argv) > 1 else None)
print(f"found {ident['model']} {ident['device']} v{ident['version']} at {ip}")
session = call("POST", "/pair/request", {"posId": "QS-1", "posLabel": "Quickstart", "clientNonce": secrets.token_hex(8)})
pin = input("PIN shown on the terminal: ").strip()       # no clientPubKey → cleartext tokenSecret (SDKs send one)
paired = call("POST", "/pair/confirm", {"sessionId": session["sessionId"], "pin": pin})
token = (paired["tokenId"], hmac.new(bytes.fromhex(paired["tokenSecret"]), paired["tokenId"].encode(), hashlib.sha256).hexdigest())
print(f"paired as {paired['posId']}  tokenId={paired['tokenId']}")
ref = f"QS-{int(time.time())}"
sale = call("POST", "/pay", {"ref": ref, "amountCents": 15000}, token)
print(f"pay     {sale['status']}  RC={sale.get('responseCode', '-')}  STAN={sale.get('stan', '-')}  card={sale.get('cardNumber', '-')}")
if sale["status"] != "approved": sys.exit("not approved: nothing to reverse")
rev = call("POST", "/reversal", {"ref": ref + "-R", "originalRef": ref, "stan": sale["stan"]}, token)
print(f"reverse {rev['status']}  RC={rev.get('responseCode', '-')}")
