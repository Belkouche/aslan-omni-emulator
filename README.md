# Aslan Omni Terminal Emulator

A fake Aslan Omni payment terminal that runs on your machine. It answers on the
LAN exactly like the real terminal app (v1.3.5): UDP discovery, PIN pairing,
signed `OMNI-TOKEN` requests, payments, reversals and admin routes. With
`--relay` it also acts as a cloud-onboarded device, so an app that goes through
the Aslan Omni cloud can drive it too. You can build and test a POS integration
or an SDK without a Sunmi terminal, without a card and without moving money.

- One file: `omni_emulator.py`. Python 3.10+, standard library only, no install.
- HTTP on port **8080** and UDP discovery on **8481**, bound to `0.0.0.0` like the
  terminal, so other machines on your LAN can reach it.
- Approves everything by default; `--mode` and [magic amounts](#9-magic-amounts)
  produce declines, cancels, timeouts and reversal failures on demand.

**Fidelity rule.** When an SDK and the terminal disagree, the emulator does what
the terminal does. Examples: `POST /reverse` is a 404 (the route is `/reversal`),
and `GET /admin/pos` returns `createdAt`, never `pairedAt`. If your code works
against the emulator but an SDK expects otherwise, the SDK is the one to fix.

---

## Contents

1. [Quickstart](#1-quickstart)
2. [The two halves](#2-the-two-halves)
3. [Discovery (UDP 8481)](#3-discovery-udp-8481)
4. [Pairing](#4-pairing)
5. [Signing requests (OMNI-TOKEN)](#5-signing-requests-omni-token)
6. [Payments: `/pay`](#6-payments-pay)
7. [Reversals and admin routes](#7-reversals-and-admin-routes)
8. [Modes](#8-modes)
9. [Magic amounts](#9-magic-amounts)
10. [Decline scenarios and response codes](#10-decline-scenarios-and-response-codes)
11. [Interactive mode and console](#11-interactive-mode-and-console)
12. [Cloud device (`--relay`)](#12-cloud-device---relay)
13. [All flags](#13-all-flags)
14. [Error reference](#14-error-reference)
15. [State, tests and self-check](#15-state-tests-and-self-check)
16. [Known differences from a real terminal](#16-known-differences-from-a-real-terminal)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Quickstart

Start the emulator (approves every payment):

```bash
python3 omni_emulator.py
```

The banner shows the LAN URL (`http://192.168.x.x:8080`) and the admin key. In
another terminal, run the example client [`examples/quickstart.py`](examples/quickstart.py).
It discovers the terminal, pairs, takes a 150.00 MAD payment and reverses it:

```bash
$ python3 examples/quickstart.py            # optional argument: terminal IP (default: broadcast)
found P3 EMU-mybox v1.3.5 at 192.168.24.242
PIN shown on the terminal: 887829           # ← type the PIN printed by the emulator
paired as QS-1  tokenId=1af191ac-9b20-4645-b3b6-54983f022ec1
pay     approved  RC=000  STAN=968676  card=516794******3315
reverse reversed  RC=000
```

The emulator prints the PIN in a box, then logs one line per request:

```
  ┌────────────────────────────────────────────┐
  │                PAIRING PIN                 │
  ├────────────────────────────────────────────┤
  │  POS     : Quickstart (QS-1)               │
  │  PIN     : 887829                          │
  │  Expires : 120 s                           │
  └────────────────────────────────────────────┘
18:54:01  INFO     [192.168.24.242] POST /pay ref=QS-1794250441 amount=15000 → approved RC=000 STAN=968676
18:54:01  INFO     [192.168.24.242] POST /reversal ref=QS-1794250441-R originalRef=QS-1794250441 stan=968676 → reversed RC=000
```

With an Omni SDK, point its LAN transport at the emulator (discovery finds it, or
use the IP from the banner), call `pairLan` with the PIN, then `pay`.

---

## 2. The two halves

```
omni_emulator.py
├─ LAN half (default)                         what a POS on the same network talks to
│   ├─ UDP 8481   OMNI-DISC:<nonce> → identity + HMAC; OMNI-BEACON every 30 s
│   └─ HTTP 8080  /health  /pair/request  /pair/confirm
│                 /pay  /reversal  /admin/pos  /admin/pos/{tokenId}  /admin/reversal
│
└─ Cloud half (--relay [BASE])                what the Aslan Omni cloud talks to
    ├─ device token: --device-token → cache → shared demo terminal → claim flow
    ├─ SSE  GET  BASE/omni/cloud/stream            (PayCommand, ReverseCommand, Ping…)
    ├─ code POST BASE/omni/cloud/pair/initiate     (printed; your app calls pairCloud)
    └─ result POST BASE/omni/cloud/pay/{id}/result
```

Both halves share one outcome engine and one transaction store, so a payment
behaves the same whichever way it arrives. `--no-lan --relay` runs the cloud half
alone.

---

## 3. Discovery (UDP 8481)

Send a datagram `OMNI-DISC:<nonce>` to port 8481 (broadcast or unicast). The
terminal replies to the sender's address and port with compact JSON:

```json
{"device":"EMU-mybox","model":"P3","version":"1.3.5","hmac":"<hex HMAC-SHA256(discoveryKey, nonce)>"}
```

- The nonce is everything after the prefix, trimmed.
- `discoveryKey` is 32 random bytes kept in the state file; the HMAC proves it is
  the same terminal across restarts. Anything not starting with `OMNI-DISC:` is ignored.
- Every 30 s the terminal broadcasts `OMNI-BEACON:{"device","model","version"}` to
  `255.255.255.255:8481` (`--no-beacon` turns it off).
- The reply does not carry the HTTP port: clients assume 8080.

---

## 4. Pairing

Pairing turns a 6-digit PIN shown on the terminal into a long-lived POS token.

```
 POS / SDK                                        Terminal
    │ POST /pair/request                           │
    │ {posId, posLabel, clientNonce, clientPubKey?}▶│  shows the PIN (120 s)
    │ ◀──────────── 200 {sessionId, expiresIn:120} │
    │ POST /pair/confirm {sessionId, pin} ────────▶│
    │ ◀── 200 {tokenId, posId, terminalModel,      │
    │          encryptedTokenSecret | tokenSecret} │
```

- `posId`, `posLabel` and `clientNonce` are required; `clientPubKey` is optional.
  Both routes need `Content-Type: application/json` (the terminal's Ktor
  content negotiation), otherwise the answer is `500 internal error`.
- `clientPubKey` is an RSA public key (SPKI/DER, base64). When present, the secret
  comes back as `encryptedTokenSecret`: RSA-OAEP with SHA-256 and MGF1-SHA-256,
  base64. Decrypt it with your private key to get the 32-byte secret. A key that
  cannot be used gives `400 invalid clientPubKey` at confirm time.
- Without `clientPubKey` the secret comes back as `tokenSecret`, 64 lowercase hex
  characters. Current SDKs always send a key; the example client does not.
- `posId` and `posLabel` are taken from the request session, never from the
  confirm body.
- Limits: the PIN is valid 120 s; 5 wrong PINs lock the session (next attempt:
  `invalid or expired session`); 5 pairing calls per IP per 60 s, shared by
  request and confirm; 15 confirms per 60 s for the whole terminal.

Keep `tokenId` and the secret. The secret is not used directly: derive
`tokenHmac = HMAC-SHA256(key = secret, message = tokenId)` as lowercase hex, and
sign with its bytes (next section).

---

## 5. Signing requests (OMNI-TOKEN)

`/pay`, `/reversal` and the `/admin/pos` routes need:

```
Authorization: OMNI-TOKEN tokenId=<tokenId>,ts=<unix seconds>,sig=<hex>
```

```
message = tokenId + ":" + ts + ":" + METHOD + ":" + path + ":" + sha256_hex(raw body)
sig     = hex( HMAC-SHA256( key = bytes.fromhex(tokenHmac), message ) )
```

- `path` is the request path **without the query string** (`/pay`, not `/pay?x=1`).
- The body hash is over the exact bytes sent (empty body for GET and DELETE).
- `sig` must be lowercase hex; the comparison is exact.
- The three parts may come in any order; spaces around them are ignored.
- `ts` must be within ±300 s of the terminal clock.

The terminal checks in this order and stops at the first failure (all `401`):
`missing or invalid Authorization` → `missing tokenId` → `missing ts` (absent or
not an integer) → `missing sig` → `timestamp out of window` → `unknown token` →
`invalid signature`. The timestamp is checked before the token is looked up.

A minimal signer is in [`examples/quickstart.py`](examples/quickstart.py) (`call()`).

---

## 6. Payments: `/pay`

```http
POST /pay
{"ref":"ORDER-1001","amountCents":15000,"cashierId":"c1","tillId":"t1","description":"…","printReceipt":false}
```

`ref` and `amountCents` are required. The terminal does not validate the amount.
The answer is always `200` with a PayResult (null fields are omitted):

| status | fields present |
|--------|----------------|
| `approved` | `responseCode` `000`, `authNumber`, `stan`, `cardNumber` (`516794******3315`), `cardScheme` (`MASTERCARD`), `terminalId`, `merchantId`, `transactionDate` (`dd/MM/yyyy`), `transactionTime` (`HH:mm:ss`) |
| `declined` | `responseCode` (e.g. `100`, `116`) |
| `cancelled` | `responseCode` `099` (customer cancelled on the terminal) |
| `timeout` | nothing: NapsPay never answered, the outcome is unknown |

Every result also carries `ref` and `amountCents`. There is no `rrn` on the LAN
(NapsPay app2app never fills it) and no `error` status.

**Idempotency by `ref`.** Retrying with the same `ref` is safe:

| stored status | retry gets |
|---------------|-----------|
| `approved`, `reversed` | the stored result again, `200` (the amount is not compared) |
| `pending` (in progress) | `409 ref already in progress` |
| `declined`, `cancelled`, `timeout` | a new charge with the same `ref` (no money moved the first time) |

Two concurrent requests with the same `ref`: the second gets `409` immediately.
After a `timeout`, retry with the **same** ref: if the first attempt was really
approved you get it back instead of charging twice.

---

## 7. Reversals and admin routes

**`POST /reversal`** (OMNI-TOKEN) — `{"ref":"<new ref>","originalRef":"ORDER-1001","stan":"968676"}`

The original must exist, have been paid by the same POS (`posId`) and have the
same STAN, otherwise `403 not authorized to reverse this transaction`. Answer:
`200 {"status":"reversed"|"declined","ref":<your ref>,"responseCode"?}`. The
original transaction keeps its status (the terminal does not update it).

**`POST /admin/reversal`** (header `X-Admin-Key`, printed in the banner) —
`{"originalRef":"…","reversalRef":"…"}`. For the terminal operator; skips the
ownership check.

| original | answer |
|----------|--------|
| unknown | `404 transaction not found` |
| `pending` (stuck) | marked `cancelled`: `200 {"status":"cancelled","ref":originalRef,"note":"pending cleared locally"}` |
| no STAN (declined, timeout…) | `422 no STAN on record — cannot reverse` |
| otherwise | `200 {"status":"reversed"|"declined","ref":reversalRef,"responseCode"?}` |

Wrong or missing key: `401 invalid admin key`.

**`GET /admin/pos`** (OMNI-TOKEN) — the caller's own entry only:
`{"pos":[{"tokenId","posId","posLabel","createdAt":<epoch seconds>}]}`.

**`DELETE /admin/pos/{tokenId}`** (OMNI-TOKEN) — a POS can revoke only itself:
`204` (empty body); another token's id gives `403 forbidden`.

---

## 8. Modes

One mode per process (`--mode`). To test several, run several emulators with
different ports and state files.

| `--mode` | Payments | Reversals |
|----------|----------|-----------|
| `approve` (default) | approved | reversed, RC `000` |
| `decline` | declined, RC `100` (do not honour) | reversed |
| `error` | declined with `--code` (name or number, default `909`) | reversed |
| `cancel` | cancelled, RC `099` | reversed |
| `timeout` | wait `--timeout-after` s (default 90, like NapsPay), then `timeout` | reversed |
| `reversal_decline` | approved | declined with `--code` (default `909`) |
| `reversal_timeout` | approved | wait `--timeout-after` s, then declined with no response code (cloud: `timeout`) |
| `interactive` | you choose at the console ([§11](#11-interactive-mode-and-console)) | reversed |

`--delay S` adds S seconds of simulated card time before every outcome
(default 0 for CI; ~3 makes demos feel real). Magic amounts override the mode
for payments.

```bash
python3 omni_emulator.py --mode error --code insufficient_funds
python3 omni_emulator.py --mode timeout --timeout-after 5
python3 omni_emulator.py --mode reversal_decline --code 912 --lan-port 8090 --udp-port 8491 --state-file /tmp/omni-b.json
```

---

## 9. Magic amounts

The **last two digits of `amountCents`** fix the payment outcome, whatever the
mode, on LAN and cloud alike. These are documented in the SDK READMEs, so test
suites can script every branch with amounts alone:

| Amount ends in | Outcome |
|----------------|---------|
| `00` | approved |
| `05` | declined, RC `005` |
| `08` | cancelled, RC `099` |
| `51` | timeout, answered immediately (no 90 s wait) |

Any other ending falls through to `--mode`.

---

## 10. Decline scenarios and response codes

Use a name or a number with `--code`, or pick by number in interactive mode.
Same table as the NAPS terminal emulator:

| # | Name | Code | Meaning |
|---|------|------|---------|
| 1 | `insufficient_funds` | 116 | Not enough balance |
| 2 | `wrong_pin` | 117 | Incorrect PIN |
| 3 | `pin_attempts_exceeded` | 106 | Too many wrong PINs |
| 4 | `expired_card` | 101 | Card expired |
| 5 | `suspected_fraud` | 102 | Fraud suspected |
| 6 | `do_not_honour` | 100 | Generic issuer refusal |
| 7 | `card_not_active` | 118 | Card not registered |
| 8 | `transaction_not_allowed` | 120 | Not permitted at terminal |
| 9 | `exceeds_limits` | 121 | Withdrawal limit exceeded |
| 10 | `invalid_cvv` | 183 | Invalid CVV |
| 11 | `system_down` | 909 | System failure |
| 12 | `issuer_unavailable` | 912 | Issuer unavailable |
| 13 | `server_error` | 995 | Server processing error |
| | `cancelled` | 280 | Alternative amount cancelled |
| | `record_not_found` | 302 | Record not found |
| | `already_cancelled` | 482 | Transaction already cancelled |
| | `approved` | 000 | Approved |

Any other code works as a number (e.g. `--code 265`). The terminal treats
`000`, `001`, `003` and `007` as approved; `099` is its customer-cancel code.

---

## 11. Interactive mode and console

`--mode interactive` asks you what to do with each payment (LAN `/pay` or cloud
`PayCommand`):

```
  ┌── Payment from 192.168.1.20 (Till 1) ──────────────────────────
  │  Ref    : ORDER-1001
  │  Amount : 150.00 MAD
  │  Card   : 516794******3315
  ├─────────────────────────────────────────────────
  │  [a] Approve
  │  [ 1] Decline — Insufficient funds (116)
  │  ...
  │  [c] Customer cancels (099)
  │  [t] Timeout (no answer from NapsPay)
  └─────────────────────────────────────────────────
  Choice →
```

Type `a` or Enter to approve, a menu number to decline, `c` to cancel, `t` for a
timeout, or a raw code (`116`) or name (`insufficient_funds`). With no answer
after 120 s the payment is approved. Prompts come one at a time; a second request
with the same `ref` gets `409` without a second prompt.

When `--relay` is on, typing `p` + Enter (outside a prompt) asks the cloud for a
new pairing code.

---

## 12. Cloud device (`--relay`)

Use this when your app talks to the **Aslan Omni cloud**
(`https://staging-api.aslanpay.ma/omni`) rather than to a terminal on its LAN —
the same path a production app uses to reach a terminal in another city.

### Who is who

```
   ┌────────────┐   pairCloud / pay / reverse   ┌──────────────────────────┐   PayCommand (SSE)   ┌──────────────┐
   │  Your app  │ ────────────────────────────▶ │   staging-api.aslanpay   │ ───────────────────▶ │   emulator   │
   │ (Omni SDK) │ ◀──────────────────────────── │   .ma/omni  (the cloud)  │ ◀─────────────────── │ (--relay)    │
   └────────────┘        PayResult               └──────────────────────────┘   result (POST)      └──────────────┘
        caller                                          the broker                    the terminal
```

Your app never talks to the emulator directly. The emulator connects **out** to
the cloud (no inbound ports), waits for commands on a long-lived SSE stream, runs
the outcome engine and posts the result back.

### Step 1 — start it

```bash
python3 omni_emulator.py --no-lan --relay        # staging, zero setup
python3 omni_emulator.py --relay https://my-api.example.com   # another API (…/omni is added)
```

```
[cloud] using shared demo terminal (Emulator E2E Merchant) — token cached
[cloud] SSE connected
  ┌────────────────────────────────────────────┐
  │             CLOUD PAIRING CODE             │
  │  Code    : A1B2C3D4                        │
```

### Step 2 — pair your app with the printed code

```ts
const omni = new OmniClient({ tokenStore: new MemoryTokenStore(),
                              cloudBaseUrl: 'https://staging-api.aslanpay.ma/omni' });
const target = await omni.pairCloud({ pairingCode: 'A1B2C3D4' });
```

The code expires after 120 s; type `p` + Enter for a new one.

### Step 3 — pay, reverse

```ts
await omni.pay(target, { ref: 'A', amountCents: 1000 });   // …00 → approved
await omni.pay(target, { ref: 'B', amountCents: 1005 });   // …05 → declined (RC 005)
await omni.pay(target, { ref: 'C', amountCents: 1051 });   // …51 → timeout
```

### What the device does (as the terminal's CloudSyncManager)

- Every request goes to `BASE + "/omni" + path` (unless BASE already ends in
  `/omni`); the signature covers the bare path, because nginx strips `/omni`.
- Device signing: `key = utf8(deviceToken)`, `tokenId = deviceToken`, same
  message shape as [§5](#5-signing-requests-omni-token), body hash over the exact bytes sent.
- On start: `POST /cloud/pair/initiate {}` once, code printed.
- On each SSE (re)connect: `GET /cloud/commands/pending`, and a queued command is
  run as a `PayCommand`. Reconnects back off 3 s, doubling to 60 s.
- `PayCommand {commandId, ref, amountCents}`: dropped if `commandId`/`ref` is missing or
  the amount ≤ 0. A `ref` already completed on this terminal is re-posted from the
  store (no second charge); otherwise the outcome engine runs and the result is posted.
- `ReverseCommand {commandId, ref, originalRef, stan}`: reversal outcome posted as
  `reversed` / `declined` (`timeout` if NapsPay never answered).
- `Ping` → `POST /cloud/ping {}`. `BrandingUpdated` and `PairingRevoked` are logged.
- Result: `POST /cloud/pay/{commandId}/result` with `status` plus, when known,
  `responseCode, authNumber, stan, rrn, cardNumber, cardScheme, txDate, txTime,
  acquirerMerchantId, acquirerTerminalId, transactionNumber`. One attempt, no
  retry, HTTP status logged — like the terminal.

### Device token

Acquisition order:

1. `--device-token T` (or `OMNI_DEVICE_TOKEN`). `--save-token` writes it to the token file.
2. The token file (`~/.aslan-omni-emulator/device.json`) if its `cloudBase` targets the same API.
3. The shared demo terminal from `GET /omni/devices/demo-token` (staging). No secret
   lives in this repo; everyone using it drives the same demo device, which cannot
   touch a real merchant. A 404 means none is configured: falls through to 4.
4. The claim flow: `POST /omni/devices/claim {"serialNumber","model","appVersion"}`,
   the claim URL is printed, status is polled every 3 s; the token is saved on the
   first `activated` answer (it is delivered only once). An expired claim (404/410)
   starts a new one. Activation itself happens in the dashboard.

`--reset` deletes the token file (and re-onboards when `--relay` is also given).

---

## 13. All flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--host ADDR` | `0.0.0.0` | Bind address for HTTP and UDP |
| `--lan-port N` | `8080` | HTTP port |
| `--udp-port N` | `8481` | Discovery port (also the beacon target port) |
| `--no-lan` | off | No HTTP/UDP (cloud-only; needs `--relay`) |
| `--no-beacon` | off | Do not broadcast `OMNI-BEACON` |
| `--serial S` | `EMU-<hostname>` | Device serial (discovery, claim) |
| `--model M` | `P3` | `terminalModel` / discovery model |
| `--terminal-id ID` | `00000001` | Acquirer terminal id on approvals |
| `--merchant-id ID` | `000000000001` | Acquirer merchant id on approvals |
| `--mode MODE` | `approve` | See [§8](#8-modes) |
| `--code CODE` | `909` | RC for `error` / `reversal_decline`: number or scenario name |
| `--delay S` | `0` | Simulated card time before every outcome |
| `--timeout-after S` | `90` | Wait before a timeout in `timeout` / `reversal_timeout` |
| `--state-file PATH` | `~/.aslan-omni-emulator/terminal.json` | Tokens, transactions, keys |
| `--fresh` | off | Start from empty state (new keys, no tokens); overwrites the file |
| `--relay [BASE]` | off (`https://staging-api.aslanpay.ma`) | Also run as a cloud device |
| `--device-token T` | `$OMNI_DEVICE_TOKEN` | Cloud device token |
| `--token-file PATH` | `~/.aslan-omni-emulator/device.json` | Device token cache |
| `--save-token` | off | Persist `--device-token` |
| `--reset` | off | Delete the cached device token |
| `--selfcheck` | off | Pair, sign a payment and answer a probe in-process, then exit |
| `--debug` | off | Log every request and response body |

---

## 14. Error reference

Every error body is `{"error":"<message>"}`, except unknown routes (`404`, empty
body). JSON is compact, null fields are omitted, and like the terminal's Gson the
characters `= < > & '` inside strings are escaped as `=` etc. (any JSON
parser decodes them).

| Route | Status | `error` | When |
|-------|--------|---------|------|
| any signed route | 401 | `missing or invalid Authorization` | no header, or not `OMNI-TOKEN …` |
| | 401 | `missing tokenId` / `missing ts` / `missing sig` | part absent (`ts` also when not an integer) |
| | 401 | `timestamp out of window` | `ts` more than 300 s off |
| | 401 | `unknown token` | `tokenId` never paired or revoked |
| | 401 | `invalid signature` | wrong key, path, body or uppercase hex |
| `/pair/request`, `/pair/confirm` | 429 | `rate limit exceeded` | 5 per IP per 60 s (shared); confirm also 15 per 60 s overall |
| `/pair/confirm` | 400 | `invalid or expired session` | unknown, used, expired, or locked after 5 wrong PINs |
| | 400 | `wrong pin` | PIN mismatch (attempt counted) |
| | 400 | `invalid clientPubKey` | the key from `/pair/request` cannot encrypt |
| `/pay` | 409 | `ref already in progress` | same `ref` still pending |
| `/reversal` | 403 | `not authorized to reverse this transaction` | unknown original, other POS, or STAN mismatch |
| `/admin/reversal` | 401 | `invalid admin key` | `X-Admin-Key` missing or wrong |
| | 404 | `transaction not found` | unknown `originalRef` |
| | 422 | `no STAN on record — cannot reverse` | original never approved |
| `DELETE /admin/pos/{id}` | 403 | `forbidden` | `{id}` is not the caller's token |
| | 404 | `token not found` | token already gone |
| any | 500 | `internal error` | malformed JSON, missing required field, wrong type, pairing without `Content-Type: application/json` |
| unknown route | 404 | (empty body) | e.g. `POST /reverse`, `GET /pay`, `/pay/` |

---

## 15. State, tests and self-check

State lives in `~/.aslan-omni-emulator/terminal.json` (`--state-file`): paired
tokens, transactions, the admin key and the discovery key, so pairings and
idempotency survive restarts. Transactions still `pending` for more than 2 min at
start-up become `timeout` (their `ref` can be retried). `--fresh` starts empty.
Pairing sessions are kept in memory only. The state file and the device-token
file hold secrets, so they are written `0600` (and `~/.aslan-omni-emulator`, when
the emulator creates it, `0700`).

Run the test suite (stdlib `unittest`; pytest works too; ~15 s):

```bash
python3 -m unittest -v test_omni_emulator
python3 -m pytest -q
```

It starts real servers on ephemeral ports and tests the cloud half against an
in-process fake of the cloud API that verifies device signatures and the `/omni`
prefix.

`python3 omni_emulator.py --selfcheck` pairs, signs a payment and answers a
discovery probe in-process, and prints `selfcheck: OK`.

**SDK test suites.** Start one emulator per mode on its own ports and state file,
e.g. `python3 omni_emulator.py --lan-port 8091 --udp-port 8491 --state-file /tmp/omni-ci.json --fresh --no-beacon`,
and drive outcomes with magic amounts. Read the PIN from the log (`PIN     : 123456`)
if the suite pairs non-interactively.

---

## 16. Known differences from a real terminal

- **NapsPay is simulated.** Fixed card `516794******3315` / `MASTERCARD`, random
  auth number, STAN and transaction number; nothing is printed.
- **Magic `…51` times out immediately**; only `--mode timeout` waits the 90 s.
- **No cloud upload of LAN transactions**, no heartbeat, no branding downloads, no
  refunds (VPS only), no ECR/TLV mode.
- **Pairing sessions are in memory** (the terminal keeps them in its database),
  so a restart forgets PINs that were shown but not confirmed.
- **Wrong method on a known path is 404.** The terminal's Ktor router may answer
  `405` there; do not rely on either.
- **Same `ref` on LAN and cloud at the same moment**: the second is declined with
  `responseCode` `DUPLICATE`, as the terminal's NapsPay bridge does.
- `terminalModel` is `--model` (the terminal sends `Build.MODEL`).

---

## 17. Troubleshooting

| Symptom | Likely cause and fix |
|---------|----------------------|
| `Cannot bind 0.0.0.0 (HTTP 8080 / UDP 8481)` | Another emulator or service holds the port. Use `--lan-port` / `--udp-port`, or find it with `lsof -nP -iTCP:8080 -sTCP:LISTEN`. |
| Discovery finds nothing | Firewall blocking UDP 8481, or client and emulator on different subnets. Unicast the probe to the banner's LAN IP. |
| `500 internal error` on `/pair/request` | Missing `posId`/`posLabel`/`clientNonce`, or no `Content-Type: application/json`. |
| `401 invalid signature` | Signing the path with its query string, re-serializing the body after signing, using the raw secret instead of `tokenHmac`, or uppercase hex. |
| `401 timestamp out of window` | Client clock more than 5 min off. |
| `401 unknown token` | The state file was reset (`--fresh`, different `--state-file`) or the POS revoked itself. Pair again. |
| `409 ref already in progress` | A payment with that `ref` is still running (`--delay`, `timeout` or `interactive` mode). |
| `403` on `/reversal` | Reversing another POS's sale, a wrong STAN, or an unknown `originalRef`. |
| `404` on `/reverse` | The route is `/reversal`. |
| Payment hangs ~90 s | `--mode timeout` (shorten with `--timeout-after`) or `interactive` waiting for you. |
| Cloud: `cannot get a device token` | BASE unreachable, or the API has no demo device and the claim call failed. |
| Cloud: `result post … → HTTP 401` | Wrong or deactivated device token; `--reset` and onboard again. |

Run with `--debug` to log every request and response body.

---

## Requirements

- Python 3.10+
- No external packages
