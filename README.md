# OT Anomaly Radar

A protocol-native OT anomaly detector for **Modbus/TCP and S7comm**: it
parses real wire format into structured transactions (function code,
register, value, request↔response), builds features from what each
transaction *means* in the context of its own session, and scores it for
anomalies — instead of treating OT traffic as generic bytes-per-second
time series. Works offline (pcap files, same protocols) and live (sniffs
a SPAN/mirror port continuously — see "Live monitoring" below).

**[Try it in your browser →](https://KhabibullaevMurodilla.github.io/anomaly-radar/)**
(live once Pages is enabled — see below) — drop in your own `.pcap` and
get results instantly. No install, no upload: the entire parser and the
population-relative session detector run as client-side JavaScript, so
the file never leaves your machine. **Multi-protocol** — both Modbus/TCP
(port 502) and S7comm (port 102) are parsed and scored client-side, same
as the CLI and live monitor. The page opens pre-loaded with a real
reconnaissance scan captured at a security conference as a worked
example (both protocols from that capture). Until Pages is on, open `ot-radar.html` directly from a local
clone — the pcap-upload part works straight from disk; only the worked
example needs it served over HTTP (browsers block `fetch()` on a bare
`file://` page), so serve it locally instead if you want that too:
`python -m http.server -d .` then open `localhost:8000/ot-radar.html`.

This page is already set up in `docs/` for GitHub Pages — once this repo
is pushed and public, turn on Pages (Settings → Pages → Deploy from
branch → `main` / `docs`) and it's live at
`https://<your-username>.github.io/ot-anomaly-detector/`, no account
needed to view it. If `ot-radar.html` changes, copy it into `docs/` again
(CI checks the two stay identical):

```bash
cp ot-radar.html docs/index.html
```

The worked example's data file (`real_demo_raw.json`) is just raw,
unscored transactions from the real 4SICS capture — the page's own JS
parses and scores them the same way it would your upload. Regenerate it
with:

```bash
python scripts/export_raw_demo.py   # needs data/real/4sics-151022-modbus-only.pcap — see "Getting real OT data"
cp real_demo_raw.json docs/real_demo_raw.json
```

## Why protocol-native, not generic time series

Most network anomaly detection treats traffic as byte/packet-count time
series, which throws away almost everything meaningful about an
industrial protocol: *which* register got written, *what* value, by
*which* function code, compared to *this specific* controller's own
history. Cisco's APEX research (2024) found that a 10.5M-parameter model
given protocol-structured input matched a 151M-parameter model given raw
packet features — the representation mattered more than scale. This
project builds that representation for Modbus/TCP and S7comm and proves
the resulting pipeline end-to-end, honestly, including where it still
fails.

## What's actually working right now

| Stage | What it does | Status |
|---|---|---|
| Parse (Modbus/TCP) | MBAP header + function-specific PDU → joined request/response transactions | Working — validated against both synthetic traffic and real captures (FIFO-per-connection matching, not transaction-ID matching — see below) |
| Parse (S7comm) | TPKT/COTP/S7 header → joined Job/Ack-Data transactions, hand-rolled (scapy has no S7comm dissector) | Working — validated against the 4SICS capture's real S7comm traffic (106k+ transactions). Scoped to framing + function code + success/failure, not full item-level read/write address decoding — see `parser/s7comm_parser.py`'s docstring for the exact simplifications |
| Features | Per-session (src→dst:unit) protocol-aware features: novel function/address, session-relative timing and value z-scores, rolling event rate | Working (Modbus only — the per-transaction detector below hasn't been extended to S7comm yet) |
| Per-transaction score | Isolation Forest baseline over those features | Working, modest: 20.8% precision / 23.3% recall on planted synthetic anomalies, Modbus only. **Known blind spot**: misses an attacker who is anomalous from their first packet (confirmed on a real scan) |
| Session-level score | Population-relative: scores a whole session against its peers on the same PLC **and protocol** | Working, both protocols — correctly flags a real reconnaissance scan that the per-transaction model missed, zero false positives on legitimate sessions (Modbus or S7comm) tested so far |
| Evaluate | Precision/recall/confusion matrix against ground truth, no inflated point-adjust scoring | Working for synthetic Modbus data; real-world precision/recall still needs a labeled real dataset (see TODO.md) |
| Live monitoring | Sniffs a SPAN/mirror port directly (no pcap file), both protocols, scores a rolling window, alerts once per newly-flagged session | Working — verified end-to-end over real loopback traffic, not just unit-tested; see "Live monitoring" below |
| Browser tool (`ot-radar.html`) | Drag-and-drop pcap analysis, entirely client-side | Working, both protocols — parser and session detector for Modbus/TCP and S7comm both ported to client-side JS, mirroring the Python modules line for line. Classic pcap only (not pcapng yet) — see Roadmap |

The headline number is not meant to impress — it's meant to be honest. A
lot of published OT anomaly-detection benchmarks (SWaT/WADI especially)
are inflated by a scoring protocol called "point adjustment" that counts
a whole attack window as detected if any single point in it is flagged.
This project evaluates without that adjustment, reports what's actually
missed, and treats the gap as the roadmap (see below), not something to
hide.

## Quickstart

The fastest way to try this is the [browser tool](#) above — drop in a pcap, no setup. The rest of this section is the Python CLI, which the browser tool is a JS port of and which is what you'd use for batch processing, CI, live monitoring, or precision/recall evaluation against ground truth.

```bash
pip install -r requirements.txt

# Run BOTH detectors on the included synthetic traffic (this is the default)
python main.py data/synthetic/modbus_traffic.pcap

# Add precision/recall against the planted ground truth
python main.py data/synthetic/modbus_traffic.pcap --labels data/synthetic/ground_truth_labels.csv

# Run it on your own Modbus/TCP pcap
python main.py path/to/your_capture.pcap

# Just one detector at a time
python main.py path/to/your_capture.pcap --transactions-only
python main.py path/to/your_capture.pcap --sessions-only

# Run the test suite (some real-capture tests skip if data/real/ is empty — see below)
python -m pytest tests/ -v
```

The default command runs **both** detectors and labels each result by
what it actually catches — this matters because they have different, real
blind spots (see "Validated against real traffic" below): the
per-transaction detector catches a transaction that's unusual for its own
session's history, and the per-session detector catches a whole session
that's unusual compared to its peers, which is the one that catches an
attacker who's anomalous from their very first packet.

## Live monitoring (no pcap file needed)

Both the CLI and the browser tool above are *offline*: something has to
capture traffic to a file first. `--watch` instead sniffs Modbus/TCP
directly off an interface and scores it continuously — point it at a
SPAN/mirror port or a tap on the OT switch, not a random workstation NIC,
or it won't see PLC-to-PLC traffic:

```bash
sudo python main.py --watch eth0
sudo python main.py --watch eth0 --window 600 --interval 30   # bigger window, less frequent re-scoring
```

It reuses the exact same FIFO request/response matcher and the same
peer-group session scorer as the file-based pipeline (one implementation,
not two that can drift apart — see `parser/modbus_parser.py`'s
`StreamingModbusMatcher`), just run incrementally: completed transactions
land in a rolling window (default 5 minutes), the window is re-scored
every `--interval` seconds, and each session is alerted on once, the
moment it first crosses the threshold — not once per tick for as long as
it stays flagged.

```
[watch] sniffing 'tcp port 502' on eth0 — scoring a 300s rolling window every 15s. Ctrl-C to stop.
[ALERT] session 192.168.2.166->192.168.88.60:1 flagged — max|z|=4.13 vs its peers (n=16590, req/s=7.98, exc%=100%, func_codes=10)
```

Needs root or `CAP_NET_RAW` to open the interface — same requirement as
`tcpdump` or Wireshark, not something specific to this tool:

```bash
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))   # alternative to running as root
```

Verified end-to-end against real loopback traffic (crafted legitimate
Modbus sessions plus a scan-like session, sent live and sniffed by
`LiveMonitor` while running), not just unit-tested in isolation — see
`tests/test_live_monitor.py`.

## Project layout

```
parser/modbus_parser.py       Modbus/TCP wire-format parser; exposes
                               StreamingModbusMatcher, shared by pcap parsing,
                               live capture, and parser/multi.py
parser/s7comm_parser.py       S7comm wire-format parser (hand-rolled — scapy has
                               no S7comm dissector); same StreamingXMatcher shape
parser/pcapreader.py          Fast raw pcap/pcapng reader (no scapy) — what makes
                               parsing a 371k-packet real capture take seconds,
                               not minutes; see its docstring
parser/multi.py                Runs both protocols' matchers over one capture,
                               combined into one DataFrame with a `protocol` column
live/monitor.py                Live mode: sniffs an interface (both protocols),
                               scores a rolling window, alerts on newly-flagged sessions
features/build_features.py    Protocol-native, session-aware feature builder (Modbus only)
models/baseline_detector.py   Per-transaction Isolation Forest + evaluation harness (Modbus only)
models/session_detector.py    Per-session, population-relative detector (catches
                               what the per-transaction one structurally can't) —
                               multi-protocol, scores Modbus and S7comm sessions
data/synthetic/                Synthetic traffic generator + ground truth (used by
                                the Python test suite and CLI examples)
data/real/                     Real captures for local testing — gitignored,
                                not bundled; see "Getting real OT data" below
ot-radar.html                  Browser tool: parser + session detector ported to
                                client-side JS, drag-and-drop pcap upload
real_demo_raw.json             Raw (unscored) transactions for ot-radar.html's
                                worked example — see scripts/export_raw_demo.py
docs/                          GitHub Pages copy of ot-radar.html
scripts/export_raw_demo.py     Regenerates real_demo_raw.json from data/real/
main.py                        CLI entry point — runs both detectors by default
tests/                         pytest suite (parser, features, both detectors)
TODO.md                        Honest status and the real next steps
```

## Validated against real Modbus/TCP traffic, including a real attack

This parser and both detectors have been run against real captures, not
only the synthetic generator — and real traffic found two real bugs and
one real structural blind spot, each fixed, not just noted.

**Bug 1 — transaction matching.** Many genuine Modbus masters (especially
serial-to-TCP gateways) never increment the Modbus transaction ID — one
real capture had 141/141 requests at `transId=0`. An earlier version of
this parser joined request↔response on that ID and silently mispaired
them whenever it repeated. Fixed by matching **FIFO order per TCP
connection** instead, which is what the protocol actually guarantees.
Regression test: `tests/test_real_captures.py`.

**Bug 2 — a merge-key explosion.** The Modbus transaction ID isn't
reliably unique on real traffic (see Bug 1), so code that joined two
dataframes on `transaction_id` cross-joined into tens of millions of rows
on a real 50k-transaction capture and OOM-killed the process. Fixed by
assigning a genuinely unique `row_id` at parse time and using that for
every internal join; `transaction_id` is kept only as a display field.
Regression test: `tests/test_parser.py::test_row_id_is_always_unique...`.

**Structural blind spot — found using a real captured attack as a
positive control, not assumed.** A public 4SICS security-conference
capture contains an unmistakable reconnaissance scan: one host
(`192.168.2.166`) swept 4 PLCs through function codes 0–255 (many not
even valid Modbus codes) at ~370 requests/second for 47 minutes, drawing
a 99% exception-response rate. `models/baseline_detector.py` flags it at
2.5% — indistinguishable from noise — because its features are
*session-relative*: an attacker who is anomalous from their first packet
never deviates from their own history, by construction. That's exactly
why `models/session_detector.py` exists: it scores whole sessions against
their *peers* hitting the same PLC instead. Run against the same capture,
it puts the attacker's sessions at the top (z = 3.0–4.8) while leaving
every legitimate session, synthetic or real, unflagged. Full story,
including the statistical caveat the session detector has (small peer
groups cap how extreme a z-score can mathematically get): `TODO.md`.

**S7comm turned out to be the majority protocol, not a minor addition.**
Checked directly with `tshark -z io,phs`, not assumed: the same 4SICS
capture has 106,421 S7comm frames against 99,472 Modbus frames — a
Modbus-only parser was only ever seeing about half this network's real
industrial traffic. The S7comm parser was validated against that real
traffic the same way: it correctly decoded 106k+ real transactions
(mostly `read_var` polling, a handful of `write_var`), and `scripts/`-style
cross-checking confirmed the fast raw-byte reader and a scapy-fed path
agree exactly on the same traffic (`tests/test_s7comm_parser.py`).

```bash
python main.py data/real/your_capture.pcap   # runs both detectors by default, both protocols at the session level
```

## Getting real OT data

The synthetic traffic generator exists because real OT capture datasets
carry their own licenses, and several widely-cited ones (SWaT, WADI,
EPIC) are request-gated and research-only — not something to bundle or
train a commercial model on without reading the terms first. Checked
directly (not assumed):

- **automayt/ICS-pcap** (GitHub) — small, public-domain Modbus test
  captures (including a function-code fuzz test and one of the captures
  this project's bugs were found against). Easiest way to get started:
  ```bash
  mkdir -p data/real
  curl -o data/real/modbus-fuzz-part2.pcap \
    https://media.githubusercontent.com/media/automayt/ICS-pcap/master/MODBUS/MODBUS-TestDataPart2/MODBUS-TestDataPart2.pcap
  ```
- **4SICS ICS lab pcaps** (Netresec) — freely downloadable, attribution
  requested, no restrictive license found. The 200MB
  `4SICS-GeekLounge-151022.pcap` is the one the real scan above came
  from, and it's majority S7comm, not Modbus (see above) — extract
  whichever protocol you need (or both, in one filter):
  ```bash
  tshark -r in.pcap -Y "tcp.port==502" -F pcap -w modbus-only.pcap
  tshark -r in.pcap -Y "tcp.port==102" -F pcap -w s7comm-only.pcap
  ```
  `-F pcap` matters: tshark defaults to pcapng output, which this
  project's parsers do support, but classic pcap is smaller and what the
  committed test fixtures use.
- **CIC Modbus 2023** (UNB) — permissive, redistribution and commercial
  use allowed, citation required, and **has labeled attacks** — the
  missing piece for a real precision/recall number (see Roadmap).
- **SWaT / WADI / EPIC** — signed request forms, typically research-only.
  Don't train anything commercial on these without reading the actual
  agreement.

None of this is bundled in the repo (`data/real/` is gitignored) to avoid
redistributing third-party capture files.

## Roadmap (see TODO.md for the full version)

1. **Get a labeled real dataset** (CIC Modbus 2023) for a real
   precision/recall number — real-traffic validation so far has been
   qualitative (does it catch a known-real attack) rather than a
   measured rate, because the captures validated against don't ship
   ground truth.
2. The per-transaction detector's remaining miss (a burst of
   individually-plausible requests within an established session) needs
   a model that reasons over the *sequence*, not a per-transaction score.
3. Evaluate a small open time-series foundation model (Toto, Chronos-2,
   or IBM's Tiny Time Mixers) on the same feature frame — but design it
   to inherit the session-detector's population-relative comparison, not
   just the per-transaction one, or it inherits the same blind spot.
4. ~~Port the S7comm parser to `ot-radar.html`'s client-side JS~~ — done;
   the browser tool now covers both protocols like the CLI and live
   monitor do. Still classic-pcap-only there (not pcapng) — the Python
   side's `parser/pcapreader.py` has pcapng support, JS doesn't yet.
5. Extend the per-transaction detector (features + Isolation Forest) to
   S7comm — right now only the session-level detector is multi-protocol.
6. A third protocol: DNP3 is the natural next one (common in North
   American utility SCADA, unlike Modbus/S7comm which skew industrial/
   European) — no scapy dissector for it either, so it'd follow the same
   hand-rolled approach as s7comm_parser.py.
7. Alerting integrations for live mode (webhook, syslog) — it currently
   only prints to stdout.

## License

MIT — see [LICENSE](LICENSE).
