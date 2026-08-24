#!/usr/bin/env python3
"""Syncs data/cve_dataset.yaml from the NVD CVE API 2.0 (issue #12).

Crimp does *not* call any CVE API live during a scan - the chosen use case
is offline/air-gapped firmware scanning, so this script is a periodic,
manual (for now) offline step that regenerates a small, crimp-native local
dataset the C code (src/core/cve_match.c) can read without needing a JSON
parser or network access.

Usage:
    python scripts/sync_cve_dataset.py [--api-key KEY] [--out data/cve_dataset.yaml]

Without an API key, NVD rate-limits to ~5 requests per 30s - this script
paces itself accordingly (one request every 6s) and will take a few minutes
for the current product list. An API key (free, from
https://nvd.nist.gov/developers/request-an-api-key) raises that to 50/30s.

Scope, deliberately: only products crimp's own component identification
(src/core/component_identify.c) can ever report a version for - OpenSSL,
BusyBox, Dropbear. Linux kernel is NOT included: the NVD linux_kernel CPE
has 19,000+ CVEs (checked 2026-08-24), overwhelmingly scoped to specific
subsystems/build configs a bare version-range match can't distinguish -
syncing all of them would make CVE matching mostly noise for this
component. Revisit only with a real scoping strategy (e.g. only kernel
5.x+, or a subsystem-aware match), not just "sync everything".

Per CVE, per matching cpeMatch entry: an *exact* pinned version in the CPE
criteria string (not a wildcard) becomes an "==VERSION" condition; a
wildcard version with versionStart/EndIncluding/Excluding bounds becomes a
comma-separated range (e.g. ">=1.0.0,<1.1.1n"). A wildcard version with NO
range bounds at all (fully unbounded - rare, mostly very old CVE records)
is skipped: too ambiguous to be a useful signal, and not what modern NVD
entries look like anyway.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# (crimp component name, NVD CPE vendor:product)
PRODUCTS = [
    ("OpenSSL", "openssl:openssl"),
    ("BusyBox", "busybox:busybox"),
    ("Dropbear", "dropbear_ssh_project:dropbear_ssh"),
]


def fetch_page(cpe_vendor_product, start_index, api_key):
    url = (
        f"{NVD_API}?virtualMatchString=cpe:2.3:a:{cpe_vendor_product}"
        f"&resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
    )
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def fetch_all(cpe_vendor_product, api_key, delay_sec):
    """Paginates through every CVE for one product. Returns the raw list of
    NVD 'vulnerabilities' entries."""
    out = []
    start_index = 0
    while True:
        for attempt in range(3):
            try:
                page = fetch_page(cpe_vendor_product, start_index, api_key)
                break
            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                print(f"  warning: request failed ({e}), retrying...", file=sys.stderr)
                time.sleep(delay_sec * 2)
        else:
            raise RuntimeError(f"giving up on {cpe_vendor_product} after 3 failed attempts")

        vulns = page.get("vulnerabilities", [])
        out.extend(vulns)
        total = page.get("totalResults", len(out))
        start_index += len(vulns)
        print(f"  fetched {start_index}/{total}", file=sys.stderr)
        if start_index >= total or not vulns:
            break
        time.sleep(delay_sec)
    return out


def best_severity(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            sev = entries[0].get("baseSeverity")
            # CVSS v3+ allows a "NONE" baseSeverity for a 0.0-scored entry -
            # not one of crimp's own low/medium/high/critical buckets, and
            # not meaningfully actionable as a finding either. Treat it the
            # same as no severity at all (skip the CVE) rather than writing
            # a value the C matcher (src/core/cve_match.c) doesn't recognize.
            if sev and sev.upper() != "NONE":
                return sev.lower()
    return None


def english_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def cpe_matches_for_product(cve, cpe_vendor_product):
    """Yields (affected_condition_string) for every cpeMatch entry in this
    CVE's configurations that (a) targets our product, (b) is marked
    vulnerable, and (c) yields either an exact version or a real range."""
    prefix = f"cpe:2.3:a:{cpe_vendor_product}:"
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                if not criteria.startswith(prefix):
                    continue
                fields = criteria.split(":")
                # cpe:2.3:a:vendor:product:version:update:... -> index 5 is version
                version_field = fields[5] if len(fields) > 5 else "*"

                if version_field not in ("*", "-"):
                    yield f"=={version_field}"
                    continue

                conditions = []
                if "versionStartIncluding" in match:
                    conditions.append(f">={match['versionStartIncluding']}")
                if "versionStartExcluding" in match:
                    conditions.append(f">{match['versionStartExcluding']}")
                if "versionEndIncluding" in match:
                    conditions.append(f"<={match['versionEndIncluding']}")
                if "versionEndExcluding" in match:
                    conditions.append(f"<{match['versionEndExcluding']}")
                if conditions:
                    yield ",".join(conditions)
                # else: fully unbounded wildcard, no range info - skip (see module docstring)


def yaml_quote(s):
    """Double-quoted YAML scalar escaping for the handful of control
    characters that can actually appear in NVD text (backslash, double
    quote, newline, tab) - this dataset's schema is fixed and fully
    controlled by this script, so a general-purpose YAML emitter isn't
    needed, just correct escaping for these fields."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return f'"{s}"'


def build_dataset(api_key, delay_sec):
    components = []
    for i, (name, cpe_vendor_product) in enumerate(PRODUCTS):
        if i > 0:
            time.sleep(delay_sec)  # pace across products too, not just within one product's pages
        print(f"fetching {name} ({cpe_vendor_product})...", file=sys.stderr)
        raw_vulns = fetch_all(cpe_vendor_product, api_key, delay_sec)

        cves = []
        for v in raw_vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            severity = best_severity(cve)
            description = english_description(cve)
            if not cve_id or not severity or not description:
                continue
            for affected in cpe_matches_for_product(cve, cpe_vendor_product):
                cves.append((cve_id, affected, severity, description))

        print(f"  {len(cves)} affected-range entries from {len(raw_vulns)} CVEs", file=sys.stderr)
        components.append((name, cves))
    return components


def write_yaml(components, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# Generated by scripts/sync_cve_dataset.py - do not edit by hand.\n")
        f.write("# Source: NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)\n")
        f.write("components:\n")
        for name, cves in components:
            f.write(f"  - name: {name}\n")
            f.write("    cves:\n")
            for cve_id, affected, severity, description in cves:
                f.write(f"      - id: {cve_id}\n")
                f.write(f"        affected: {yaml_quote(affected)}\n")
                f.write(f"        severity: {severity}\n")
                f.write(f"        description: {yaml_quote(description)}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-key", default=None, help="NVD API key (optional, raises rate limit)")
    parser.add_argument("--out", default="data/cve_dataset.yaml")
    args = parser.parse_args()

    delay_sec = 0.6 if args.api_key else 6.0
    components = build_dataset(args.api_key, delay_sec)
    write_yaml(components, args.out)

    total_cves = sum(len(cves) for _, cves in components)
    print(f"wrote {args.out}: {total_cves} affected-range entries across {len(components)} components")


if __name__ == "__main__":
    main()
