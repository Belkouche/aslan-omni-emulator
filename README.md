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

```bash
python3 omni_emulator.py --no-lan --relay
```

No credentials, no dashboard step. The emulator connects to real
`staging-api.aslanpay.ma` as a **shared demo terminal** and is ready in seconds.

1. With no `--device-token` and no cache, the emulator fetches the shared demo terminal's
   token from the public endpoint and connects:
   ```
   [Cloud] using shared demo terminal (Emulator E2E Merchant) — token cached.
   [Cloud] SSE connected.
   ```
2. It prints a **pairing code**:
   ```
   [Cloud] pairing code: A1B2C3D4  (enter via pairCloud)
   ```
3. Your app calls `pairCloud({ pairingCode })` against real staging to obtain its own apiKey
   (the emulator isn't involved in that leg).
4. `pay` runs through the real staging cloud loop — command pushed to the emulator, outcome
   posted back:
   ```
   pay({ amountCents: 1000 })   → approved
   pay({ amountCents: 1005 })   → declined
   ```

> The demo terminal is shared and read-only-ish: everyone who runs the emulator against
> staging drives the same demo device. That's fine for integration testing — nothing you do
> touches a real merchant. To use your **own** provisioned terminal instead, pass
> `--device-token` (see [Device token](#device-token--re-onboarding)).

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
