#!/usr/bin/env python3
"""
snowmelt - ServiceNow node-log guest-access hunter (end to end).

One command: raw node log(s) -> cleaned IP set -> parsed transactions ->
classification -> actor profiles, content fingerprint, session attribution.

No instance access, no database; flat CSV/JSON outputs. No external binaries.

PIPELINE
  Phase 0  Discover + hygiene   extract every IPv4 token, classify, and KEEP
           (00_ip_hygiene/)      only valid public IPs that actually appear as a
                                 transaction `source:`. Everything dropped is
                                 written with a reason for review.
  Phase 1  Parse                normalise guest transactions into one record
           (01_parsed/)          schema (transactions.csv / .jsonl).
  Phase 2  Classify             per-IP verdict, endpoint tiers, served-vs-probed
           (02_classification/)  evidence.
  Phase 3  Analyse              actor_profiles, content_fingerprint,
           (03_analysis/)        session_attribution, exposure_inventory, timeline.
  run_manifest.json             config, input hashes, counts (chain of custody).

NORMALISED TRANSACTION RECORD (the spine; one row per guest transaction)
  ts, source_file, line_no, thread, session_id, txid, txn_marker, txn_num,
  source_ip, user, endpoint, endpoint_raw, referer_slug, widget_sysid,
  r_status, render_size, type, tier, disposition, served

IP HYGIENE REASON CODES (00_ip_hygiene/ip_rejected.csv)
  INVALID_SYNTAX  octet>255 / leading zero / malformed (catches version strings)
  LAST_OCTET_ZERO last octet .0 (network base, not a host)
  UNSPECIFIED     0.0.0.0/8
  LOOPBACK        127.0.0.0/8
  LINK_LOCAL      169.254.0.0/16
  CGNAT_SHARED    100.64.0.0/10
  PRIVATE         RFC1918 10/8, 172.16/12, 192.168/16
  MULTICAST       224.0.0.0/4
  DOC_OR_BENCHMARK 192.0.2/24, 198.51.100/24, 203.0.113/24, 198.18/15, ...
  RESERVED_BOGON  other reserved / non-global space
  NON_SOURCE      valid public but never seen as a `source:` (likely a version
                  number or incidental token, not a client) -> quarantined
  MANUAL_EXCLUDE  operator-supplied --exclude-ips (e.g. confirmed MID servers)

Usage:
  ./snowmelt.py --logs <FILE_OR_DIR> --out <OUTDIR>
              [--glob '*.txt'] [--exclude-ips ip1,ip2]
              [--content-floor 256] [--emit-jsonl] [--no-hash]
"""

import argparse
import collections
import csv
import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone

VERSION = "1.0.0"

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

# ---------------------------------------------------------------- parser grammar
RE_HEAD = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\(\d+\)\s+(\S+)\s+([0-9A-Fa-f]{32})")
RE_TXID = re.compile(r"\btxid\s*=\s*([0-9A-Fa-f]+)")
RE_TXN = re.compile(r"\*\*\*\s*(Start|End)\s+#(\d+)\s+(.*?),\s*user\s*[:=]", re.I)
RE_USER = re.compile(r"\buser\s*[:=]\s*([^,]+?)\s*(?:,|$)", re.I)
RE_STATUS = re.compile(r"\br_status\s*[:=]\s*(\d{3})", re.I)
RE_RENDER = re.compile(r"\brender_size\s*[:=]\s*([0-9][0-9.,]*)", re.I)
RE_SOURCE = re.compile(r"\bsource\s*[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})")
RE_TYPE = re.compile(r"\btype\s*[:=]\s*([^,]+?)\s*(?:,|$)", re.I)
RE_SESSION = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
IP_TOKEN = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])")
RECT_RE = re.compile(r"/api/now/sp/rectangle/([0-9a-f]{32})", re.I)

# ---------------------------------------------------------------- classification
SCANNER_RE = re.compile(
    r"(?i)(?:\.php$|/\.git|/\.env|/wp-|/wp_|global-protect|\+cscot\+|/sslmgr"
    r"|\.avif$|/sitemap\.xml$|/swagger|/api-?docs|/api/doc|/api/json$"
    r"|/riddle|hellopress|/sonicos/|filemanager)")
CHROME = {x.lower() for x in {
    "/auth_redirect.do", "/login", "/login.do", "/logout.do",
    "/logout_redirect.do", "/external_logout_complete.do",
    "/validate_multifactor_auth_code.do", "/session_timeout.do",
    "/nav_to.do", "/navpage.do", "/api/navpage.do", "$uxapp.do",
    "/amb_session_setup.do", "/api/now/ui/presence",
    "/api/now/uisession/touch-session", "/login_with_sso.do",
    "/sys_ux_page_registry.do", "/sys_ux_app_route.do"}}
TIER3 = {"/midservercheck.do"}
DATA_API_PREFIX = ("/api/now/sp/page", "/api/now/sp/rectangle", "/xmlhttp.do",
                   "/angular.do", "/api/now/graphql",
                   "/legacy_date_time_choices_processor.do")

# IP hygiene reference networks
CGNAT = ipaddress.ip_network("100.64.0.0/10")
DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "198.18.0.0/15", "192.88.99.0/24")]


# ---------------------------------------------------------------- record schema
TXN_FIELDS = ["ts", "source_file", "line_no", "thread", "session_id", "txid",
              "txn_marker", "txn_num", "source_ip", "user", "endpoint",
              "endpoint_raw", "referer_slug", "widget_sysid", "r_status",
              "render_size", "type", "tier", "disposition", "served"]


@dataclasses.dataclass
class Txn:
    ts: str = ""
    source_file: str = ""
    line_no: int = 0
    thread: str = ""
    session_id: str = ""
    txid: str = ""
    txn_marker: str = ""
    txn_num: str = ""
    source_ip: str = ""
    user: str = ""
    endpoint: str = ""
    endpoint_raw: str = ""
    referer_slug: str = ""
    widget_sysid: str = ""
    r_status: object = None       # int or None
    render_size: object = None    # float or None
    type: str = ""
    tier: str = ""
    disposition: str = ""
    served: bool = False


def base_endpoint(raw):
    return raw.split(" referer")[0].split("?")[0].strip()


def referer_slug(raw):
    if " referer:" not in raw:
        return ""
    r = raw.split(" referer:", 1)[1].strip().split("?")[0].strip().strip("/")
    if r.endswith(".do") or r in ("", "auth_redirect.do", "login.do"):
        return ""
    return r


def classify_endpoint(ep):
    low = ep.lower()
    if SCANNER_RE.search(ep):
        return "SCANNER"
    if low in CHROME:
        return "CHROME"
    if low in TIER3:
        return "TIER3_INFRA"
    if low == "/$sp.do" or low.startswith("/api/now/sp/"):
        return "TIER1_PORTAL"
    if (low.startswith("/api/now/graphql") or "/related_list_edit" in low
            or low.startswith("/api/sn_now_assist") or low.startswith("/api/caen/")
            or low in {"/xmlhttp.do", "/angular.do",
                       "/legacy_date_time_choices_processor.do"}
            or low.startswith("/api/now/connect/") or low.startswith("/api/")):
        return "TIER2_DATA"
    return "OTHER"


def classify_ip(s):
    """Return (reason, keep_if_source: bool). keep is provisional; NON_SOURCE
    quarantine and MANUAL_EXCLUDE are applied later."""
    try:
        ip = ipaddress.ip_address(s)   # rejects octet>255 and leading zeros
    except ValueError:
        return ("INVALID_SYNTAX", False)
    if ip.version != 4:
        return ("INVALID_SYNTAX", False)
    if int(s.split(".")[-1]) == 0:
        return ("LAST_OCTET_ZERO", False)
    if ip.is_unspecified:
        return ("UNSPECIFIED", False)
    if ip.is_loopback:
        return ("LOOPBACK", False)
    if ip.is_link_local:
        return ("LINK_LOCAL", False)
    if ip in CGNAT:
        return ("CGNAT_SHARED", False)
    if ip.is_private:
        return ("PRIVATE", False)
    if ip.is_multicast:
        return ("MULTICAST", False)
    if any(ip in n for n in DOC_NETS):
        return ("DOC_OR_BENCHMARK", False)
    if ip.is_reserved or not ip.is_global:
        return ("RESERVED_BOGON", False)
    return ("VALID_PUBLIC", True)


def parse_render(num_str):
    if num_str is None:
        return None
    try:
        return float(num_str.replace(",", ""))
    except ValueError:
        return None


def parse_guest_line(path, line_no, line):
    """Parse a physical line into a Txn iff it is a guest transaction."""
    m_user = RE_USER.search(line)
    if not m_user or m_user.group(1).strip().lower() != "guest":
        return None
    t = Txn(source_file=path, line_no=line_no, user="guest")
    h = RE_HEAD.match(line)
    if h:
        t.ts, t.thread, t.session_id = h.group(1), h.group(2), h.group(3)
    else:
        ms = RE_SESSION.search(line)
        t.session_id = ms.group(1) if ms else ""
    mx = RE_TXID.search(line)
    t.txid = mx.group(1) if mx else ""
    mt = RE_TXN.search(line)
    if mt:
        t.txn_marker, t.txn_num, raw_ep = mt.group(1), mt.group(2), mt.group(3).strip()
    else:
        raw_ep = ""
    t.endpoint_raw = raw_ep
    t.endpoint = base_endpoint(raw_ep)
    t.referer_slug = referer_slug(raw_ep)
    mr = RECT_RE.search(t.endpoint)
    t.widget_sysid = mr.group(1) if mr else ""
    ms2 = RE_SOURCE.search(line)
    t.source_ip = ms2.group(1) if ms2 else ""
    mstat = RE_STATUS.search(line)
    t.r_status = int(mstat.group(1)) if mstat else None
    mrend = RE_RENDER.search(line)
    t.render_size = parse_render(mrend.group(1)) if mrend else None
    mty = RE_TYPE.search(line)
    t.type = mty.group(1).strip() if mty else ""
    return t


def decide_served(t, floor):
    """SERVED if content of real size was returned; PROBED if stub/blocked."""
    if t.render_size is None or t.render_size <= 0:
        return False
    status_ok = t.r_status is not None and 200 <= t.r_status <= 299
    rest_soap_noresult = t.r_status is None and t.type.lower() in ("rest", "soap")
    if not (status_ok or rest_soap_noresult):
        return False
    return t.render_size >= floor


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def iter_log_files(logs, glob_pat):
    if os.path.isfile(logs):
        yield logs
        return
    pat = re.compile(re.escape(glob_pat).replace(r"\*", ".*").replace(r"\?", ".") + r"$",
                     re.I)
    for root, _dirs, files in os.walk(logs):
        for name in files:
            if pat.match(name):
                yield os.path.join(root, name)


def w_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser(
        description="snowmelt - end-to-end ServiceNow node-log guest-access hunter.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", required=True, help="node log file or directory")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--glob", default="*.txt")
    ap.add_argument("--exclude-ips", default="",
                    help="comma-separated confirmed-legit IPs to quarantine")
    ap.add_argument("--content-floor", type=int, default=256)
    ap.add_argument("--emit-jsonl", action="store_true",
                    help="also write 01_parsed/transactions.jsonl")
    ap.add_argument("--no-hash", action="store_true",
                    help="skip SHA-256 of input files")
    args = ap.parse_args()

    if not os.path.exists(args.logs):
        sys.exit(f"[error] --logs not found: {args.logs}")
    exclude = {ip.strip() for ip in args.exclude_ips.split(",") if ip.strip()}

    d0 = os.path.join(args.out, "00_ip_hygiene")
    d1 = os.path.join(args.out, "01_parsed")
    d2 = os.path.join(args.out, "02_classification")
    d3 = os.path.join(args.out, "03_analysis")
    for d in (d0, d1, d2, d3):
        os.makedirs(d, exist_ok=True)

    files = list(iter_log_files(args.logs, args.glob))
    if not files:
        sys.exit(f"[error] no files matched {args.glob} under {args.logs}")

    # ---- Phase 0/1: single streaming pass ----
    all_ips = collections.Counter()         # every IPv4 token seen
    ip_sample = {}                           # ip -> (file, line_no, snippet)
    source_ips = set()                       # IPs seen as a `source:`
    txns = []                                # guest Txn records
    lines_scanned = 0
    file_meta = []

    for path in files:
        if not args.no_hash:
            digest = sha256_file(path)
        else:
            digest = ""
        size = os.path.getsize(path) if os.path.isfile(path) else 0
        file_meta.append({"path": path, "sha256": digest, "bytes": size})
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, 1):
                    lines_scanned += 1
                    for m in IP_TOKEN.finditer(line):
                        ip = m.group(1)
                        all_ips[ip] += 1
                        if ip not in ip_sample:
                            ip_sample[ip] = (path, line_no, line.strip()[:120])
                    if "guest" in line or "GUEST" in line or "Guest" in line:
                        t = parse_guest_line(path, line_no, line)
                        if t is not None:
                            if t.source_ip:
                                source_ips.add(t.source_ip)
                            txns.append(t)
        except OSError as e:
            print(f"[warn] cannot read {path}: {e}", file=sys.stderr)

    # ---- Phase 0: IP hygiene ----
    kept, rejected = set(), []
    reason_counts = collections.Counter()
    for ip, occ in all_ips.items():
        reason, ok = classify_ip(ip)
        appeared = ip in source_ips
        if ok and ip in exclude:
            reason, ok = "MANUAL_EXCLUDE", False
        elif ok and not appeared:
            reason, ok = "NON_SOURCE", False
        if ok:
            kept.add(ip)
            reason_counts["VALID_PUBLIC_KEPT"] += 1
        else:
            reason_counts[reason] += 1
            f, ln, snip = ip_sample.get(ip, ("", 0, ""))
            rejected.append([ip, reason, occ, "Y" if appeared else "N", f, ln, snip])

    w_csv(os.path.join(d0, "ip_rejected.csv"),
          ["ip", "reason", "occurrences", "appeared_as_source",
           "first_file", "first_line", "sample_context"],
          sorted(rejected, key=lambda r: (r[1], r[0])))
    with open(os.path.join(d0, "ip_candidates_kept.txt"), "w", encoding="utf-8") as fh:
        for ip in sorted(kept, key=lambda x: ipaddress.ip_address(x)):
            fh.write(ip + "\n")
    with open(os.path.join(d0, "ip_hygiene_summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"distinct_ip_tokens_seen": len(all_ips),
                   "kept_public_source_ips": len(kept),
                   "rejected_by_reason": dict(reason_counts)}, fh, indent=2)

    # ---- restrict to kept IPs, classify each txn ----
    analysis = []
    for t in txns:
        if t.source_ip not in kept:
            continue
        t.tier = classify_endpoint(t.endpoint)
        t.served = decide_served(t, args.content_floor)
        if t.tier in ("TIER1_PORTAL", "TIER2_DATA"):
            t.disposition = "SERVED" if t.served else "PROBED"
        analysis.append(t)

    # ---- Phase 1: transactions.csv (+ jsonl) ----
    def row(t):
        return [t.ts, t.source_file, t.line_no, t.thread, t.session_id, t.txid,
                t.txn_marker, t.txn_num, t.source_ip, t.user, t.endpoint,
                t.endpoint_raw, t.referer_slug, t.widget_sysid,
                "" if t.r_status is None else t.r_status,
                "" if t.render_size is None else (int(t.render_size)
                    if float(t.render_size).is_integer() else t.render_size),
                t.type, t.tier, t.disposition, "Y" if t.served else "N"]
    w_csv(os.path.join(d1, "transactions.csv"), TXN_FIELDS, (row(t) for t in analysis))
    if args.emit_jsonl:
        with open(os.path.join(d1, "transactions.jsonl"), "w", encoding="utf-8") as fh:
            for t in analysis:
                fh.write(json.dumps(dataclasses.asdict(t)) + "\n")

    # ---- Phase 2: verdict / tiers / served evidence ----
    per_ip = collections.defaultdict(lambda: {"txn": 0, "succ": 0, "other": 0,
                                              "sessions": []})
    for t in analysis:
        s = per_ip[t.source_ip]
        if t.r_status is not None:
            s["txn"] += 1
            if t.served and t.tier in ("TIER1_PORTAL", "TIER2_DATA"):
                s["succ"] += 1
                if t.session_id:
                    s["sessions"].append(t.session_id)
            elif t.r_status is None:
                s["other"] += 1
        else:
            s["other"] += 1
    vrows = []
    for ip, s in sorted(per_ip.items()):
        verdict = ("GUEST_RENDER" if s["succ"] else
                   "PROBE_ONLY" if s["txn"] else "NO_TXN_DATA")
        vrows.append([ip, verdict, s["txn"], s["succ"], s["other"],
                      ";".join(dict.fromkeys(s["sessions"]))])
    w_csv(os.path.join(d2, "verdict.csv"),
          ["source_ip", "verdict", "txn_entries", "successful_renders",
           "non_txn_entries", "success_session_ids"], vrows)

    ep_agg = collections.defaultdict(lambda: {"tier": "", "hits": 0, "served": 0,
                                              "probed": 0, "ips": set(),
                                              "sessions": set(), "bytes": 0.0,
                                              "sbytes": 0.0})
    served_rows = []
    for t in analysis:
        if t.render_size is None or t.render_size <= 0:
            continue
        a = ep_agg[t.endpoint]
        a["tier"] = t.tier
        a["hits"] += 1
        a["ips"].add(t.source_ip)
        if t.session_id:
            a["sessions"].add(t.session_id)
        a["bytes"] += t.render_size
        if t.served:
            a["served"] += 1
            a["sbytes"] += t.render_size
        else:
            a["probed"] += 1
        if t.tier in ("TIER1_PORTAL", "TIER2_DATA"):
            served_rows.append([t.tier, t.disposition, t.source_ip, t.session_id,
                                t.endpoint, "" if t.r_status is None else t.r_status,
                                int(t.render_size), t.type, t.txn_num,
                                t.source_file, t.line_no])
    order = {"TIER1_PORTAL": 0, "TIER2_DATA": 1, "TIER3_INFRA": 2,
             "OTHER": 3, "CHROME": 4, "SCANNER": 5}
    w_csv(os.path.join(d2, "endpoint_tiers.csv"),
          ["tier", "endpoint", "hits", "served", "probed", "distinct_ips",
           "distinct_sessions", "served_render_bytes", "total_render_bytes"],
          [[a["tier"], ep, a["hits"], a["served"], a["probed"], len(a["ips"]),
            len(a["sessions"]), int(a["sbytes"]), int(a["bytes"])]
           for ep, a in sorted(ep_agg.items(),
                               key=lambda kv: (order.get(kv[1]["tier"], 9),
                                               -kv[1]["sbytes"]))])
    w_csv(os.path.join(d2, "guest_data_access.csv"),
          ["tier", "disposition", "source_ip", "session_id", "endpoint",
           "r_status", "render_size", "type", "txn_num", "source_file", "line_no"],
          served_rows)

    # ---- Phase 3: served TIER1/2 analytical products ----
    served = [t for t in analysis
              if t.served and t.tier in ("TIER1_PORTAL", "TIER2_DATA")]

    # content fingerprint
    fp = collections.defaultdict(lambda: {"hits": 0, "ips": set(),
                                          "sessions": set(),
                                          "eps": collections.Counter(),
                                          "pages": set()})
    for t in served:
        size = int(t.render_size)
        f = fp[size]
        f["hits"] += 1
        f["ips"].add(t.source_ip)
        f["sessions"].add(t.session_id)
        f["eps"][t.endpoint] += 1
        if t.referer_slug:
            f["pages"].add(t.referer_slug)
    w_csv(os.path.join(d3, "content_fingerprint.csv"),
          ["render_size_bytes", "fetch_count", "distinct_ips",
           "distinct_sessions", "endpoints", "attributed_pages"],
          [[size, f["hits"], len(f["ips"]), len(f["sessions"]),
            ";".join(f"{k}({v})" for k, v in f["eps"].most_common()),
            ";".join(sorted(f["pages"]))]
           for size, f in sorted(fp.items(), key=lambda kv: -kv[1]["hits"])])

    # session attribution
    sess_pages = collections.defaultdict(set)
    sgrp = collections.defaultdict(lambda: {"ip": set(), "n": 0, "b": 0})
    for t in served:
        if t.referer_slug:
            sess_pages[t.session_id].add(t.referer_slug)
        g = sgrp[t.session_id]
        g["ip"].add(t.source_ip)
        g["n"] += 1
        g["b"] += int(t.render_size)
    w_csv(os.path.join(d3, "session_attribution.csv"),
          ["session_id", "source_ip", "served_requests", "served_bytes",
           "attributed_pages", "attribution"],
          [[sid, ";".join(sorted(g["ip"])), g["n"], g["b"],
            ";".join(sorted(sess_pages.get(sid, []))),
            "labelled" if sess_pages.get(sid) else "UNATTRIBUTED"]
           for sid, g in sorted(sgrp.items(), key=lambda kv: -kv[1]["b"])])

    # exposure inventory (endpoint / portal_page / widget)
    def inv(keyfn, kind):
        agg = collections.defaultdict(lambda: {"hits": 0, "bytes": 0,
                                               "ips": set(), "sessions": set()})
        for t in served:
            k = keyfn(t)
            if not k:
                continue
            a = agg[k]
            a["hits"] += 1
            a["bytes"] += int(t.render_size)
            a["ips"].add(t.source_ip)
            a["sessions"].add(t.session_id)
        return [[kind, k, a["hits"], a["bytes"], len(a["ips"]), len(a["sessions"])]
                for k, a in agg.items()]
    inv_rows = (inv(lambda t: t.endpoint, "endpoint")
                + inv(lambda t: t.referer_slug, "portal_page")
                + inv(lambda t: t.widget_sysid, "widget_sysid"))
    inv_rows.sort(key=lambda x: (x[0], -x[3]))
    w_csv(os.path.join(d3, "exposure_inventory.csv"),
          ["group_kind", "value", "served_hits", "served_bytes",
           "distinct_ips", "distinct_sessions"], inv_rows)

    # actor profiles
    actor = collections.defaultdict(lambda: {
        "sessions": set(), "n": 0, "bytes": 0, "days": set(), "pages": set(),
        "sizes": collections.Counter(), "data_api": 0, "eps": set(),
        "size_by_session": collections.defaultdict(set)})
    day_re = re.compile(r"(\d{4}-\d{2}-\d{2})")
    for t in served:
        a = actor[t.source_ip]
        a["sessions"].add(t.session_id)
        a["n"] += 1
        a["bytes"] += int(t.render_size)
        d = (t.ts[:10] if t.ts else (day_re.search(t.source_file) or [None]))
        day = t.ts[:10] if t.ts else (day_re.search(t.source_file).group(1)
                                      if day_re.search(t.source_file) else "?")
        a["days"].add(day)
        a["sizes"][int(t.render_size)] += 1
        a["eps"].add(t.endpoint)
        if t.referer_slug:
            a["pages"].add(t.referer_slug)
        if t.endpoint.startswith(DATA_API_PREFIX):
            a["data_api"] += 1
        a["size_by_session"][int(t.render_size)].add(t.session_id)
    actor_rows = []
    for ip, a in sorted(actor.items(), key=lambda kv: -kv[1]["bytes"]):
        flags = []
        if any(len(s) > 1 for s in a["size_by_session"].values()):
            flags.append("REPEAT_REFETCH")
        if len(a["sessions"]) >= 3 and len(a["days"]) <= 2:
            flags.append("SESSION_ROTATION")
        if len(a["eps"]) >= 4:
            flags.append("BROAD_ENUM")
        if a["data_api"] > 0:
            flags.append("DATA_API")
        if len(a["sessions"]) == 1 and a["n"] <= 3 and not flags:
            flags.append("LOW_TOUCH")
        actor_rows.append([ip, len(a["sessions"]), a["n"], a["bytes"],
                           len(a["sizes"]), a["data_api"], len(a["eps"]),
                           f'{min(a["days"])}..{max(a["days"])}',
                           ";".join(sorted(a["pages"])), ";".join(flags) or "-"])
    w_csv(os.path.join(d3, "actor_profiles.csv"),
          ["source_ip", "sessions", "served_requests", "served_bytes",
           "distinct_resource_sizes", "data_api_hits", "distinct_endpoints",
           "day_span", "pages", "flags"], actor_rows)

    # served timeline
    served.sort(key=lambda t: (t.ts or "", t.source_file, t.line_no))
    w_csv(os.path.join(d3, "served_timeline.csv"),
          ["timestamp", "source_ip", "session_id", "tier", "endpoint",
           "portal_page", "widget_sysid", "render_size", "type",
           "source_file", "line_no"],
          [[t.ts, t.source_ip, t.session_id, t.tier, t.endpoint, t.referer_slug,
            t.widget_sysid, int(t.render_size), t.type, t.source_file, t.line_no]
           for t in served])

    # ---- manifest ----
    manifest = {
        "tool": "snowmelt", "version": VERSION,
        "run_utc": datetime.now(timezone.utc).isoformat(),
        "config": {"logs": args.logs, "glob": args.glob,
                   "content_floor": args.content_floor,
                   "exclude_ips": sorted(exclude), "hashed_inputs": not args.no_hash},
        "inputs": file_meta,
        "counts": {"files": len(files), "lines_scanned": lines_scanned,
                   "distinct_ip_tokens": len(all_ips),
                   "kept_source_ips": len(kept),
                   "rejected_by_reason": dict(reason_counts),
                   "guest_transactions_kept": len(analysis),
                   "served_tier1_2": len(served)},
    }
    with open(os.path.join(args.out, "run_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    print(f"[snowmelt {VERSION}] files={len(files)} lines={lines_scanned} "
          f"ip_tokens={len(all_ips)} kept={len(kept)} "
          f"guest_txns={len(analysis)} served={len(served)}", file=sys.stderr)
    print(f"[out] {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
