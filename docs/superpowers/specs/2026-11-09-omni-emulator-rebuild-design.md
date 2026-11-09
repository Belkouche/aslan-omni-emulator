# Aslan Omni emulator rebuild — design

Date: 2026-11-09 · Branch: `rebuild/naps-style`

## Goal

Rebuild `omni_emulator.py` so it behaves like the real Aslan Omni terminal (app `aslan-omni`
`main` f8f74dd, v1.3.5) on LAN and as a cloud device against `aslan-omni-api` (`main` 5c34b1d),
structured like `../tkpay/tkpay-naps-emulator` (single stdlib file, named modes, scenario table,
interactive prompt, banner, integrator README, `examples/quickstart.py`).

Audience: external integrators **and** our SDK test suites, equally.

**Fidelity rule: strict.** When an SDK disagrees with the terminal, the emulator follows the
terminal (e.g. `POST /reverse` → 404, `/admin/pos` sends `createdAt` only). SDK bugs are fixed
in the SDKs (C# PR tracked separately).

## Constraints

- One file, Python 3.10+ stdlib only. No deps. Keep the RSA-OAEP-SHA256 encrypt code (works).
- CLI stays backward compatible where it already exists (`--lan-port`, `--udp-port`, `--no-lan`,
  `--serial`, `--relay`, `--device-token`, `--token-file`, `--save-token`, `--reset`, `--mode`,
  `--code`, `--selfcheck`, `--debug`); new flags are additive.
- Magic amounts kept (documented in SDK READMEs): suffix `00` approved, `05` declined (RC 005),
  `08` cancelled (RC 099), `51` timeout. Magic overrides `--mode` for payments.

## LAN contract (match terminal exactly)

Constants: HTTP 8080, UDP 8481, payment timeout 90 s, auth ts tolerance ±300 s, pairing session
TTL 120 s, PIN 6 digits (leading zeros allowed), 5 wrong PINs locks the session, rate limit 5/60 s
per IP shared by `/pair/request`+`/pair/confirm`, plus global 15/60 s on `/pair/confirm`.
Version string `1.3.5`, model `P3` (flag `--model`).

Binding: HTTP and UDP on `0.0.0.0` by default (`--host` to override).

Every error body: `{"error":"<string>"}`. Malformed JSON / missing required fields / any
uncaught exception → `500 {"error":"internal error"}`. Unknown route → 404. Responses omit
null fields (terminal uses Gson). Compact JSON.

| Route | Auth | Behaviour |
|---|---|---|
| `GET /health` | none | `200 {"status":"ok","version":"1.3.5","napsPay":"installed"}` |
| `POST /pair/request` | rate-limited | body `posId`, `posLabel`, `clientNonce` required; `clientPubKey` optional. `sessionId` = UUID4, stores `sha256_hex(sessionId+pin)`. Prints PIN prominently. `200 {"sessionId","expiresIn":120}`. 429 `rate limit exceeded`. |
| `POST /pair/confirm` | rate-limited | body `sessionId`, `pin`. Order: missing/used/expired → 400 `invalid or expired session`; failedAttempts ≥5 → mark used, 400 `invalid or expired session`; wrong → attempts++, 400 `wrong pin`. Success: `tokenId` UUID4, 32-byte secret, store `tokenHmac=HMAC(secret, tokenId)`; posId/posLabel **from the session**. `200 {"tokenId","posId","terminalModel"}` + `encryptedTokenSecret` (if clientPubKey; bad key → 400 `invalid clientPubKey`) else `tokenSecret` (64 lowercase hex). |
| `POST /pay` | OMNI-TOKEN | body `ref`, `amountCents` required; `cashierId`,`tillId`,`description`,`printReceipt` optional. No amount validation (terminal has none). Idempotency below. Always 200 with PayResult `{status, ref, responseCode, authNumber, stan, rrn?, cardNumber, cardScheme, terminalId, merchantId, transactionDate, transactionTime, amountCents}` (nulls omitted). 409 `ref already in progress`. |
| `POST /reversal` | OMNI-TOKEN | body `ref`, `originalRef`, `stan` required. Original must exist, belong to caller's posId and have same stan, else 403 `not authorized to reverse this transaction`. `200 {"status":"reversed"\|"declined","ref":<req.ref>,"responseCode"?}`. Does not change original's status (terminal behaviour). |
| `POST /admin/reversal` | `X-Admin-Key` | key generated at start (24 random bytes urlsafe b64, persisted), printed in banner; wrong → 401 `invalid admin key`. body `originalRef`, `reversalRef`. Not found → 404 `transaction not found`; original pending → mark cancelled, `200 {"status":"cancelled","ref":originalRef,"note":"pending cleared locally"}`; no stan → 422 `no STAN on record — cannot reverse`; else reversal → `{"status","ref":reversalRef,"responseCode"?}`. |
| `GET /admin/pos` | OMNI-TOKEN | `200 {"pos":[{"tokenId","posId","posLabel","createdAt":<epoch s int>}]}` — caller only. |
| `DELETE /admin/pos/{tokenId}` | OMNI-TOKEN | other token → 403 `forbidden`; not found → 404 `token not found`; ok → 204 empty. |

OMNI-TOKEN (LAN): `Authorization: OMNI-TOKEN tokenId=..,ts=..,sig=..` (parts split on `,`, first
`=`, trimmed, any order). 401 strings, checked in this order: `missing or invalid Authorization`,
`missing tokenId`, `missing ts` (also non-integer), `missing sig`, `timestamp out of window`
(before lookup), `unknown token`, `invalid signature`. Message
`tokenId:ts:METHOD:path:sha256hex(rawBody)`, path **without query**, key = `bytes.fromhex(tokenHmac)`,
exact lowercase hex compare (constant time).

Idempotency on `/pay` by ref (store per ref): `approved`/`reversed` → return cached 200 (amount
not compared); `pending` → 409; `declined`/`cancelled`/`timeout` → reset to pending and charge
again. Concurrent same ref → second gets 409 immediately (no second prompt in interactive).

Status mapping: approved / declined / cancelled (RC `099`) / timeout (no responseCode, all card
fields absent). No `error` status.

Persistence: tokens, admin key and transactions in `~/.aslan-omni-emulator/terminal.json`
(`--state-file`, `--fresh` to ignore). Pending rows older than 2 min become timeout on startup.

UDP discovery: datagram starting `OMNI-DISC:` → nonce = rest trimmed → unicast reply compact JSON
`{"device":serial,"model":model,"version":"1.3.5","hmac":HMAC(discoveryKey, nonce).hex}`,
discoveryKey random 32 bytes persisted. Beacon every 30 s to `255.255.255.255:<udp-port>`:
`OMNI-BEACON:{"device","model","version"}` (`--no-beacon` to disable; failures ignored).

## Outcome engine and modes

Shared by LAN `/pay` and cloud `PayCommand`. Scenario table copied from the NAPS emulator
(name → (code, label)). Default decline code `100`.

| Mode | Payment | Reversal |
|---|---|---|
| `approve` (default) | approved | reversed RC 000 |
| `decline` | declined RC 100 | reversed |
| `error --code X` | declined with X (name or number) | reversed |
| `cancel` | cancelled RC 099 | reversed |
| `timeout` | waits `--timeout-after` s (default 90) then timeout | reversed |
| `reversal_decline --code X` | approved | declined RC X (default 909) |
| `reversal_timeout` | approved | waits then declined, no responseCode |
| `interactive` | operator prompt (approve / numbered decline / cancel / timeout); auto-approve after 120 s | reversed |

`--delay S` (default 0): simulated card time before any outcome (CI uses 0; demos ~3).
Approved outcome: authNumber 6 digits, stan 6 digits, cardNumber `516794******3315`,
cardScheme `MASTERCARD`, terminalId/merchantId (`--terminal-id`/`--merchant-id`), date `dd/MM/yyyy`
time `HH:mm:ss`, transactionNumber, no rrn on LAN (app2app never fills it).

## Cloud device half (`--relay [BASE]`)

- Base default `https://staging-api.aslanpay.ma`; requests go to `BASE + "/omni" + path` unless
  BASE already ends with `/omni`; signature always over the bare path (with query if any).
- Device auth: key = utf8(deviceToken), tokenId = deviceToken, ts seconds, sha256 over the exact
  bytes sent (compact JSON).
- Token acquisition unchanged (explicit → cache → demo-token → claim). Claim body
  `{"serialNumber","model","appVersion"}`; status poll every 3 s; persist token on the first
  `activated` (delivered once); 404/410 → expired, restart claim.
- On start: `POST /cloud/pair/initiate {}` once, print code; typing `p` + Enter re-initiates.
- SSE `GET /cloud/stream`; on open → `GET /cloud/commands/pending` and handle a non-null command as
  PayCommand. Events: `PayCommand {commandId, ref, amountCents, ...}`, `ReverseCommand
  {commandId, ref, originalRef, stan}`, `Ping` → `POST /cloud/ping {}`, `BrandingUpdated` → log,
  `PairingRevoked` → log; others ignored. Each command in its own thread. Reconnect backoff 3 s
  doubling to 60 s, reset on open.
- PayCommand: drop if commandId/ref missing or amountCents ≤ 0. Ref already resolved locally
  (non-pending) → re-post stored result, no new charge. Else outcome engine → record → post.
  Timeout outcome posts `{"status":"timeout"}`.
- ReverseCommand: reversal outcome → post `reversed`/`declined`.
- Result `POST /cloud/pay/{commandId}/result`: `status` + optional `responseCode, authNumber,
  stan, rrn, cardNumber, cardScheme, txDate, txTime, acquirerMerchantId, acquirerTerminalId,
  transactionNumber`; nulls omitted. No retry on failure (terminal behaviour); log status.

## Console

Banner like NAPS (listen addresses, LAN IP hint, mode, code, admin key, cloud base). One log line
per request (`[peer] POST /pay ref=… → approved RC=000 STAN=…`), `--debug` dumps bodies. PIN and
pairing code printed in a highlighted box.

## Deliverables

1. `omni_emulator.py` rewritten.
2. `test_omni_emulator.py` rewritten: real server on ephemeral ports in-process; covers pairing
   (both secret paths, lockout, 429, TTL), every 401 string, path-without-query signing, idempotency
   matrix + 409, reversal 403/ownership, admin routes, discovery reply, every mode (with tiny
   delays), magic amounts, persistence across restart, and the cloud half against an in-process
   fake API (SSE, pending fetch, ping, result payload, re-delivery idempotency, `/omni` prefix).
3. `examples/quickstart.py`: stdlib LAN client — discover → pair (PIN typed) → pay → reverse.
4. `README.md` rewritten as an integrator guide (NAPS README structure), incl. strict-fidelity note
   and the full error table.
5. `--selfcheck` kept.

## Out of scope

C# SDK fixes (`/reverse`, `pairedAt`) — separate PR. Refunds (VPS only). Heartbeat
(`feat/monitoring`, unreleased). ECR/TLV mode. Branding downloads.
