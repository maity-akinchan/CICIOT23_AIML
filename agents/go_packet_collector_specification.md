# Capture collector and Go integration — v3

**Status:** target for M3/M4; current Go source files are empty. A collector is a
measurement source, not proof of compatibility with the trained CSV model.

## 1. Implement after defining the measurement contract

Read [the ML contract](machine_learning_pipeline_22_feature_contract.md) first.
For the existing CSV model, reproducing an original extractor requires source
provenance and parity evidence. The candidate `sentinel-pcap22-v2` equations are
for new training, not a translation of CICIoT2023 CSV column names.

A shared Python reference can support the first PCAP experiment. If Go is used
for live capture, it must match the reference on identical packets, timestamps,
window boundaries, partial-window handling, feature precision and metadata.
Do not maintain two independently evolving definitions.

## 2. Capture modes and data integrity

Implement offline PCAP first, then live capture from the target's actual
interface/network namespace. Configuration includes mode, source/interface,
server URL, sensor/session identity, credentials and the declared contract ID.
The collector must not choose a contract by the class it expects to predict.

- Group by the contract's directed endpoint/protocol key. Source and destination
  must come from an observed tuple. An interface-wide majority pair is not a flow.
- Offline extraction and live timeout behavior must have equivalent definitions.
  Preserve event time, UTC offset normalization and per-session ordering. Record
  late/out-of-order packets and apply one explicit policy in training and serving.
- Use original wire length from capture metadata. Detect `caplen < wirelen`; do
  not silently change the feature to captured length. Reject/flag headers that
  cannot be parsed completely.
- Ethernet and raw IPv4/IPv6 support may be the first tested subset. Advertise the
  supported link types. Linux cooked capture, VLANs, IPv6 extension chains,
  fragments and unsupported transport types require explicit handling or a clear
  unsupported status. An unknown IP protocol must not default to TCP.
- Keep MAC addresses nullable when absent. Never invent vendor identities or
  topology. Packet metadata is not a classifier feature unless a new model was
  explicitly trained to use it.
- Bound concurrent flow keys and queue size; expire keys. Count received,
  accepted, skipped, truncated and dropped packets/windows. Expose backlog and
  loss to the backend so low throughput cannot look like successful detection.

Candidate window size/timeout/minimum are defined in the ML specification.
Changing them is a scientific experiment requiring a new contract, not a hidden
runtime convenience flag.

## 3. Transport

Use bounded batches of at most 100 observations, stable IDs across retries and
finite HTTP timeouts. Retry transient failures with bounded backoff; surface
permanent validation/authentication errors. The backend must deduplicate before
incrementing counters or updating incidents. Preserve source/session identifiers
through persistence and UI events.

Authenticate the collector independently from the operator. Bind its token to
the permitted sensor, source mode and targets. Do not accept an untrusted client
claiming `LIVE_INTERFACE` as evidence that data can drive device actions.
Ship only base features; the shared serving preprocessor derives the four ratios.
At startup, verify the backend accepts this extractor contract. Stop inference
shipping on incompatibility and expose the error rather than silently switching
models.

## 4. Acceptance fixtures

Use hand-verifiable packets plus realistic captures:

- 100 TCP SYN packets: 54 wire bytes, 40 network+TCP header bytes, TTL 64,
  0.0001-second spacing. Expected duration 0.0099, rate 100/0.0099,
  SYN count 100, SYN share 1, standard deviation 0.
- UDP, ICMP, IPv6, TCP options, zero-duration timestamps, truncation, small files,
  EOF and timeout partials, unsupported link types and malformed captures.
- Mixed endpoint pairs proving no invented source/destination association.
- Reference/Go parity for each supported fixture, including partial windows and
  original wire lengths. Set numeric tolerances per feature and dtype.
- Retry/disconnect tests demonstrating one persisted observation and no doubled
  alerts; bounded-buffer tests with a slow/unavailable backend.

These tests establish extraction correctness under this contract only. A
successful synthetic SYN prediction does not validate learned attack detection.

## 5. Optional endpoint management (M5)

Preserve legacy integration route names only through documented adapters:
`/api/devices/register`, `/api/devices/heartbeat`, and `/ws/agent/{device_id}`.
Enrolment is operator-authorized; a setup token is not an unrestricted admin key.
Prefer authorization headers; if a compatibility query token is required for a
WebSocket client, redact URL logs and use secure transport outside the local lab.

A command ledger includes `command_id`, device/session, action, payload, actor,
reason, model/evidence reference, timestamp, deadline and lifecycle status.
Only acknowledge success after execution and state inspection. Retried command
IDs are idempotent; duplicate/foreign/stale ACKs cannot mark a new command complete.
Sandbox reports **simulated**, never **executed**.

Keep firewall/DNS/kill-switch controls disabled in the core demo. If added later,
default to sandbox, use argument arrays and validated addresses, isolate the lab,
protect loopback and backend control traffic before firewall changes, and provide
rollback. IPv4-only iptables does not establish IPv6 blocking. Downloads must
include architecture, OS/library requirements, version and checksum; cross-build
libpcap/CGO dependencies must be tested. A file path existing is not proof that
an executable works on its advertised platform.
