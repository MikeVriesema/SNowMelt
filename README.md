# SNowMelt - ServiceNow node-log guest-access hunter

Disclosure: This was built using Claude but tested against real logs

I used this to accelerate analysis of node logs in response to the June 2026 ServiceNow incident: 
https://trust.servicenow.com/notifications/1205429e-fea3-4cbf-b37b-8cd3a4e07aef

End-to-end tool: point it at a node log file or a tree of them and it discovers
the client IP set, cleans it (quarantining every exclusion for review), parses
guest transactions into one normalised record, classifies what was served vs
blocked, and produces actor profiles, a content fingerprint, and session
attribution. No ServiceNow instance access, no database, no external binaries —
flat CSV/JSON only.

## Run

```bash
python3 snowmelt.py --logs "/path/to/nodelogs" --out ./out
# options:
#   --glob '*.txt'            filename glob (case-insensitive), recursive
#   --exclude-ips a,b,c       quarantine confirmed-legit IPs (e.g. MID servers)
#   --content-floor 256       bytes at/above = SERVED, below = PROBED (stub ~116B)
#   --emit-jsonl              also write the parsed records as JSONL
#   --no-hash                 skip SHA-256 of inputs (faster; loses custody hash)
```

Requirements: Python 3.8+. Inputs are read-only. Re-running overwrites the
output directory's files.

## Output layout

```
out/
  00_ip_hygiene/
    ip_candidates_kept.txt     # the analysed IP set (one per line)
    ip_rejected.csv            # every dropped IP + reason (for review)
    ip_hygiene_summary.json    # counts per reason
  01_parsed/
    transactions.csv           # normalised guest transactions (the spine)
    transactions.jsonl         # same, JSONL (only with --emit-jsonl)
  02_classification/
    verdict.csv                # per-IP GUEST_RENDER / PROBE_ONLY / NO_TXN_DATA
    endpoint_tiers.csv         # per-endpoint served/probed rollup
    guest_data_access.csv      # TIER1/TIER2 evidence rows
  03_analysis/
    actor_profiles.csv
    content_fingerprint.csv
    session_attribution.csv
    exposure_inventory.csv
    served_timeline.csv
  run_manifest.json            # tool version, config, input hashes, counts
```

## Normalised transaction record (`01_parsed/transactions.csv`)

The spine of the tool; one row per guest transaction. Every later product is
derived from this, so it is the schema to extend or audit against.

| field | meaning |
|---|---|
| `ts` | line timestamp (`YYYY-MM-DD HH:MM:SS`) or empty |
| `source_file`, `line_no` | provenance back to the exact log line |
| `thread` | logger thread name |
| `session_id` | 32-hex session token (join key to instance-side telemetry) |
| `txid` | 12-hex transaction id |
| `txn_marker`, `txn_num` | `Start`/`End` and the `#` number |
| `source_ip` | authoritative client IP (the `source:` field) |
| `user` | always `guest` in this corpus |
| `endpoint` | normalised path (referer + query stripped) |
| `endpoint_raw` | full endpoint incl. `referer:` and query |
| `referer_slug` | portal page from the referer (e.g. `service-portal`) |
| `widget_sysid` | widget instance sys_id from `sp/rectangle/<id>` |
| `r_status` | HTTP status, or empty for REST/SOAP (not logged) |
| `render_size` | bytes returned (the content-volume measure) |
| `type` | `form` / `rest` / `soap` / `amb` / … |
| `tier` | endpoint classification (below) |
| `disposition` | `SERVED` / `PROBED` for TIER1/TIER2 rows |
| `served` | `Y` if real content returned (passes status + floor) |

## Endpoint tiers

`TIER1_PORTAL` (`/$sp.do`, `/api/now/sp/*`) · `TIER2_DATA` (GraphQL, custom
scoped APIs, AJAX processors, record-write attempts, token endpoints) ·
`TIER3_INFRA` (`/MIDServerCheck.do`) · `CHROME` (auth / nav / session keepalive)
· `SCANNER` (commodity recon: `.git`, `.env`, `wp-*`, `*.php`, vendor probes) ·
`OTHER`. Rules live in `classify_endpoint()`; add new endpoints there.

## Served vs probed

A transaction is **SERVED** when `render_size >= --content-floor` **and** either
the status is 2xx, or it is a REST/SOAP `End` line with no status (ServiceNow
does not log status for those — `render_size` is the content proxy). Below the
floor it is **PROBED**: the ~116-byte ACL-rejection stub, i.e. access attempted
but blocked.

## IP hygiene reason codes (`00_ip_hygiene/ip_rejected.csv`)

Extraction scans every IPv4 token in the logs; a candidate is **kept** only if
it is valid public space **and** actually appears as a transaction `source:`.
Drops are recorded with `occurrences`, `appeared_as_source`, and a sample line.

| reason | dropped because |
|---|---|
| `INVALID_SYNTAX` | octet >255, leading zero, malformed (catches version strings like `2.5.300.1`) |
| `LAST_OCTET_ZERO` | last octet `.0` (network base, not a host) |
| `UNSPECIFIED` | `0.0.0.0/8` |
| `LOOPBACK` | `127.0.0.0/8` |
| `LINK_LOCAL` | `169.254.0.0/16` |
| `CGNAT_SHARED` | `100.64.0.0/10` |
| `PRIVATE` | RFC1918 `10/8`, `172.16/12`, `192.168/16` |
| `MULTICAST` | `224.0.0.0/4` |
| `DOC_OR_BENCHMARK` | TEST-NET / benchmark ranges |
| `RESERVED_BOGON` | other reserved / non-global space |
| `NON_SOURCE` | valid public but never a `source:` — likely a version number or incidental token, not a client |
| `MANUAL_EXCLUDE` | operator-supplied `--exclude-ips` (e.g. confirmed MID servers) |

## Analytical products (`03_analysis/`)

- **content_fingerprint.csv** — groups served transactions by exact
  `render_size`; identical size = identical resource, so this inventories the
  distinct resources served and which were mass re-fetched, even without page
  names. Columns: `render_size_bytes, fetch_count, distinct_ips,
  distinct_sessions, endpoints, attributed_pages`.
- **session_attribution.csv** — per session: IP, served request count, bytes,
  the portal page(s) inferred from referers in the same session, and whether the
  session is `labelled` or `UNATTRIBUTED`.
- **actor_profiles.csv** — per source IP, with behavioural `flags`:
  `REPEAT_REFETCH` (same payload size across >1 session), `SESSION_ROTATION`
  (≥3 sessions in ≤2 days), `BROAD_ENUM` (≥4 distinct endpoints), `DATA_API`
  (touched widget/AJAX data), `LOW_TOUCH` (incidental). Columns include
  `sessions, served_requests, served_bytes, distinct_resource_sizes,
  data_api_hits, distinct_endpoints, day_span, pages, flags`.
- **exposure_inventory.csv** — what was returned, grouped three ways
  (`endpoint`, `portal_page`, `widget_sysid`) with hits / bytes / IPs / sessions.
- **served_timeline.csv** — served transactions in chronological order.

## Notes and limitations

- REST logging or lack thereof will hinder what you can correlate from other logs and tables.
- This does not crosscheck against transaction logs, syslog, or sysevent logs from SNOW.
- Record unit is one physical log line; logical records wrapped across lines
  would need a splitting pre-stage.
- `/$sp.do` is a POST; its page id is not in the logged URL, so some renders are
  attributable only by referer or content fingerprint.
- `render_size` is bytes rendered, a volume measure — not a record count.
- `MANUAL_EXCLUDE` and `NON_SOURCE` are the two policy levers most worth
  reviewing in `ip_rejected.csv` before trusting the kept set.
```
