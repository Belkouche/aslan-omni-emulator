# Aslan Omni Terminal Emulator

Emulates an Aslan Omni terminal — both its **LAN** side and its **cloud device** side — so
you can integrate the Aslan Omni SDK without a physical P2/P3. One file, stdlib Python
3.10+ only. No dependencies.

---

## What it is — the two halves

One script, two independent halves that share the same outcome engine, so a payment
behaves identically over LAN and cloud (the SDK's one-`PayResult` promise).

```
omni_emulator.py
├─ LAN half (default on)                      localhost, offline, self-contained
│   ├─ UDP discovery      :8481   replies to "OMNI-DISC:<nonce>"
│   └─ HTTP terminal      :8080   /health /pair/request /pair/confirm
│                                 /pay /reversal /admin/pos   (OMNI-TOKEN HMAC verified)
│
└─ Cloud half (--relay <base>)                acts as a provisioned device on staging
    ├─ device token: --device-token → cache → shared demo terminal → claim flow
    ├─ SSE client   → GET  <base>/cloud/stream                (OMNI-TOKEN signed)
    ├─ pairing code → POST <base>/cloud/pair/initiate → printed to console
    └─ on PayCommand / ReverseCommand → outcome engine → POST <base>/cloud/pay/:id/result
```

- **LAN mode** (default): point the SDK's LAN transport at `127.0.0.1`. The emulator is a
  fully self-contained fake terminal — UDP discovery + HTTP API with OMNI-TOKEN auth — so
  you can do the full discover → pair → pay → reverse flow offline.
- **Cloud mode** (`--relay`): the emulator connects **out** to real
  `staging-api.aslanpay.ma` as a provisioned *device*. Your app hits real staging cloud;
  the emulator executes the payment commands staging pushes to it.

---

## Quick start — LAN

```bash
python3 omni_emulator.py
```

Then in your app:

1. SDK `discover()` finds the emulator at `127.0.0.1`.
2. The emulator prints a pairing PIN to the console — enter it into your app's `pairLan`:
   ```
   [LAN pair] PIN for 'My POS': 418923  (type this into your app)
   ```
3. `pay({ amountCents: 1000 })` → **approved**.

Deterministic checks (see [magic amounts](#magic-amounts)):

```
pay({ amountCents: 1000 })   → approved
pay({ amountCents: 1005 })   → declined
pay({ amountCents: 1051 })   → timeout
```

---

## Quick start — Cloud (zero setup against staging)

This is the mode you want when your app talks to the **real** Aslan Omni cloud
(`staging-api.aslanpay.ma`) instead of a terminal on your LAN — the same path a production
app uses to reach a terminal sitting in another city. You get the whole cloud round-trip
without owning a physical terminal and **without any credentials or setup**.

### The mental model — who is who

There are three actors, and it helps to keep them straight:

```
   ┌────────────┐   pairCloud / pay / reverse   ┌──────────────────────────┐   PayCommand (SSE)   ┌──────────────┐
   │  Your app  │ ────────────────────────────▶ │   staging-api.aslanpay   │ ───────────────────▶ │   emulator   │
   │ (Omni SDK) │ ◀──────────────────────────── │   .ma/omni  (the cloud)  │ ◀─────────────────── │ (this tool)  │
   └────────────┘        PayResult               └──────────────────────────┘   result (POST)      └──────────────┘
        caller                                          the broker                    the terminal
```

- **Your app** is the *caller* (a merchant/POS). It never talks to the emulator directly — it
  only ever talks to the cloud.
- **Staging** is the *broker*. It holds the pairing, and when your app asks for a payment it
  pushes a command down to whichever terminal is paired, then waits for that terminal's result.
- **The emulator** is the *terminal*. It connects **out** to staging (nothing listens on your
  machine — no ports, no inbound), waits for commands over a long-lived SSE stream, runs its
  outcome engine, and posts the result back.

So a `pay()` in your app becomes: app → cloud → **SSE** → emulator → outcome → **POST** → cloud
→ app. The emulator is standing in for a real card terminal in that loop.

### Step 1 — start the emulator

```bash
python3 omni_emulator.py --no-lan --relay
```

- `--relay` turns on the cloud half and (with no `BASE` argument) points it at
  `https://staging-api.aslanpay.ma`.
- `--no-lan` turns **off** the LAN half — you don't need the UDP/HTTP terminal for a
  cloud-only run, so this keeps it quiet and avoids binding local ports.

You'll see it acquire a token and connect, all on its own:

```
[Cloud] using shared demo terminal (Emulator E2E Merchant) — token cached.
[Cloud] SSE connected.
[Cloud] pairing code: A1B2C3D4  (enter via pairCloud)
Emulator ready (mode=approve). Ctrl-C to stop.
```

**What just happened, line by line:**

1. `using shared demo terminal …` — with no `--device-token` and no cache, the emulator
   fetched a **shared demo device token** from the public endpoint
   `GET /devices/demo-token`. This is why there's no setup: staging hands out a ready-made
   demo terminal identity. (See [How zero-setup works](#how-zero-setup-works) below.)
2. `SSE connected.` — it opened the long-lived `GET /cloud/stream` connection (OMNI-TOKEN
   signed) and is now registered as an online terminal. Staging can push commands to it.
3. `pairing code: A1B2C3D4` — the terminal asked staging for a one-time pairing code (via
   `POST /cloud/pair/initiate`) and printed it. **Copy this code** — your app needs it next.

### Step 2 — pair your app to that terminal

Your app calls `pairCloud` with the code the emulator printed. This is a call to **staging**,
not to the emulator — staging looks up which terminal owns that code and issues your app an
`apiKey` scoped to it:

```ts
import { OmniClient, MemoryTokenStore } from '@belkouche/omni-react-native';

const omni = new OmniClient({
  tokenStore: new MemoryTokenStore(),
  cloudBaseUrl: 'https://staging-api.aslanpay.ma/omni',
});

// A1B2C3D4 = the code the emulator printed in Step 1
const target = await omni.pairCloud({ pairingCode: 'A1B2C3D4' });
// → { mode: 'cloud', deviceId: '…', merchantName: 'Emulator E2E Merchant', … }
```

`target` is now a handle you pass to every payment call. Your app and the emulator are linked
through staging — but notice they still never touched each other directly.

### Step 3 — take a payment (the full round-trip)

```ts
const result = await omni.pay(target, { ref: 'ORDER-1001', amountCents: 1000 });
// → { status: 'approved', authNumber: '…', stan: '…', cardNumber: '516794******3315', … }
```

While that promise is pending, this is the loop that runs:

```
your app  pay(1000) ─▶ staging  ──PayCommand──▶ emulator  (outcome engine: 1000 → approved)
your app  ◀─PayResult── staging  ◀──result POST── emulator
```

The emulator's console echoes its side:

```
[Cloud] PayCommand cmryv…qjvu → approved
```

### Step 4 — drive deterministic outcomes

The **last two digits of `amountCents`** fix the outcome (see [magic amounts](#magic-amounts)),
so you can script an entire test suite with nothing but amounts — no prompts, no config:

```ts
await omni.pay(target, { ref: 'A', amountCents: 1000 });  // …00 → approved
await omni.pay(target, { ref: 'B', amountCents: 1005 });  // …05 → declined (RC 005)
await omni.pay(target, { ref: 'C', amountCents: 1051 });  // …51 → timeout

// reverse a prior approval, and list the merchant's paired terminals — all over cloud:
await omni.reverse(target, { ref: 'V', originalRef: 'A', stan: result.stan });
await omni.listPos(target);   // → [{ kind: 'cloud', connected: true, … }]
```

That's the complete cloud surface — pair, pay, reverse, listPos — exercised end-to-end against
real staging, with the emulator playing the terminal.

### How zero-setup works

The magic in Step 1 is the shared **demo terminal**. Onboarding a real Omni device normally
means a claim + dashboard activation to mint a device token — a deliberate, human step. That's
too much friction just to try the SDK, so staging exposes one pre-provisioned demo device
through an unauthenticated `GET /devices/demo-token`:

- **Nothing secret lives in this repo.** The token is fetched at runtime, then cached to the
  local token file so subsequent runs skip the fetch.
- **The blast radius is exactly one demo terminal.** Everyone running the emulator against
  staging drives the *same* demo device. Nothing you do touches a real merchant, and the token
  can't provision or reach anything else.
- **It's a shared sandbox, not private.** If two people run the emulator at once, both are that
  one demo terminal. Fine for integration testing; not a substitute for your own device.

> **Want your own terminal instead?** Pass `--device-token <T>` (or set `OMNI_DEVICE_TOKEN`) to
> use a device you provisioned yourself, or run the full claim flow. See
> [Device token & re-onboarding](#device-token--re-onboarding).

> **Endpoint disabled?** If staging has no demo device configured, `GET /devices/demo-token`
> returns `404` and the emulator quietly falls through to the claim flow — it won't crash, it
> just can't auto-onboard.

---

## Modes

Set with `--mode` (default `approve`). Modes are overridden by
[magic amounts](#magic-amounts) when the amount matches.

| `--mode` | Behaviour | Example |
|---|---|---|
| `approve` | Approve every payment (default) | `python3 omni_emulator.py` |
| `decline` | Decline every payment (RC 005) | `python3 omni_emulator.py --mode decline` |
| `error` | Decline with a specific scenario (`--code`) | `python3 omni_emulator.py --mode error --code 909` |
| `interactive` | Prompt the operator per payment | `python3 omni_emulator.py --mode interactive` |
| `timeout` | Every payment times out | `python3 omni_emulator.py --mode timeout` |

---

## Test scenarios

For `--mode error`, pass a scenario **name** or **number** to `--code`:

| Name | Code | Name | Code |
|---|---|---|---|
| `insufficient_funds` | 116 | `transaction_not_allowed` | 120 |
| `wrong_pin` | 117 | `exceeds_limits` | 121 |
| `pin_attempts_exceeded` | 106 | `use_chip` | 265 |
| `expired_card` | 101 | `pin_failed` | 281 |
| `suspected_fraud` | 102 | `system_down` | 909 |
| `do_not_honour` | 100 | `issuer_unavailable` | 912 |
| `card_not_active` | 118 | `server_error` | 995 |

```bash
python3 omni_emulator.py --mode error --code insufficient_funds
python3 omni_emulator.py --mode error --code 116   # same thing
```

---

## Magic amounts

The **last two digits of `amountCents`** deterministically fix the outcome, overriding
`--mode`. This makes CI scriptable — no interaction, no configuration:

| Amount ends in | Outcome |
|---|---|
| `00` | approved |
| `05` | declined (RC 005) |
| `08` | cancelled |
| `51` | timeout |

Any other suffix falls through to `--mode`. Example: `amountCents: 1051` always times out,
regardless of mode.

---

## Device token & re-onboarding

The cloud device token is cached at `~/.aslan-omni-emulator/device.json`
(override with `--token-file`), holding
`{ deviceToken, deviceId, merchantId, merchantName, cloudBase }`.

Acquisition order on a `--relay` run:

1. `--device-token <T>` (or the `OMNI_DEVICE_TOKEN` env var) → use it directly. Add
   `--save-token` to persist it to the token file.
2. Else if the cached file exists and its `cloudBase` matches the target → reuse it.
3. Else → fetch the **shared demo terminal** token from `GET <base>/devices/demo-token` and
   cache it. This is the zero-setup path — it just works against staging. (The endpoint is
   inert unless the server has a demo device configured; if it 404s, the emulator falls
   through to the next step.)
4. Else → run the claim flow (prints a claim URL, polls until activated, writes the file).
   Claim activation is an external step (dashboard); use this only when onboarding your own
   dedicated terminal rather than the shared demo one.

```bash
python3 omni_emulator.py --relay --device-token omni_xxx --save-token
```

**Re-onboard** (get a fresh device token), two equivalent ways:

- **Delete the token file** — the next `--relay` launch re-runs the claim flow.
- **`--reset`** — deletes the cached file, and if `--relay` is also present, immediately
  re-runs the claim flow. Prints what it cleared.

```bash
python3 omni_emulator.py --relay --reset   # wipe cache, fresh claim
```

---

## Interactive mode

In `--mode interactive` the emulator prompts on each payment (LAN `/pay` or cloud
`PayCommand`), one at a time:

```
  ┌── Payment from cloud ─────────────────────
  │  Amount : 150.00 MAD
  │  Ref    : ORDER-1234
  ├──────────────────────────────────────────
  │  [a] Approve
  │  [ 1] Decline — Insufficient funds (116)
  │  [ 2] Decline — Wrong PIN (117)
  │  ...
  └──────────────────────────────────────────
  Choice →
```

- Type `a` (or Enter) to approve.
- Type a scenario number to decline with it.
- Type a raw code (e.g. `116`) or name (e.g. `insufficient_funds`) directly.

If no answer arrives within **120 seconds**, the payment auto-approves. Concurrent
payments are serialised — one prompt at a time.

---

## CLI reference

```
python3 omni_emulator.py [options]
```

| Flag | Default | Description |
|---|---|---|
| `--lan-port N` | `8080` | HTTP terminal port |
| `--udp-port N` | `8481` | UDP discovery port |
| `--no-lan` | off | Disable the LAN half (cloud-only run) |
| `--serial S` | `EMU-<hostname>` | Discovery / claim device id |
| `--relay [BASE]` | off (`BASE` = `https://staging-api.aslanpay.ma`) | Enable cloud half against `BASE` |
| `--device-token T` | `$OMNI_DEVICE_TOKEN` | Use this deviceToken, skip the claim flow |
| `--token-file PATH` | `~/.aslan-omni-emulator/device.json` | Token cache location |
| `--save-token` | off | Persist `--device-token` to the token file |
| `--reset` | off | Delete the cached token (and re-onboard if `--relay`) |
| `--mode M` | `approve` | `approve` \| `decline` \| `error` \| `interactive` \| `timeout` |
| `--code C` | `909` | Scenario name or number for `--mode error` |
| `--selfcheck` | off | Verify the OMNI-TOKEN scheme, then exit |
| `--debug` | off | Verbose request / field logging |

Examples:

```bash
python3 omni_emulator.py                                     # LAN only, approve all
python3 omni_emulator.py --mode interactive                  # prompt per payment (LAN)
python3 omni_emulator.py --no-lan --relay                    # cloud, zero setup (shared demo terminal)
python3 omni_emulator.py --relay                             # LAN + cloud, zero setup
python3 omni_emulator.py --relay --device-token omni_xxx --save-token   # your own terminal
python3 omni_emulator.py --relay --reset                     # wipe cache, re-acquire token
python3 omni_emulator.py --no-lan --relay --mode error --code insufficient_funds
```

---

## Notes & caveats

- **Zero-setup uses a shared demo terminal.** Against staging the emulator fetches a shared
  demo device token from `GET /devices/demo-token` — no credentials in this repo, and the
  blast radius is that one demo terminal (it can't touch a real merchant). To use your own
  provisioned terminal, pass `--device-token`.
- **Claim activation is external.** If you onboard your own device via the claim flow, the
  emulator initiates the claim and polls for status but cannot activate it itself — that leg
  happens in the dashboard (or an `internal/devices` endpoint). Once activated, the emulator
  picks up the token and continues automatically.
- **Cloud calls are OMNI-TOKEN signed** (not `Bearer`). The emulator signs every device→API
  call with the OMNI-TOKEN scheme the API verifies:
  `Authorization: OMNI-TOKEN tokenId=<...>,ts=<unix>,sig=<hex>`. If your staging is running
  an older API that expects `Bearer`, adjust accordingly.
- **Self-check** (`--selfcheck`): signs a sample request with a freshly paired token and
  verifies the emulator's own OMNI-TOKEN check accepts it — proving the LAN HMAC scheme is
  correct without a running SDK.

---

## Requirements

- Python 3.10+
- No external packages
