#!/usr/bin/env python3
"""
Process a grype output file to group critical vulnerabilities by CVE. Outputs
all grype vulnerability IDs and paths for each CVE.

The input file should be produced using:
    grype sbom:<sbom-path> -o json > grype-output.json

Return code is 1 if critical vulnerabilities found.
"""

import sys
import json
import argparse
from itertools import chain
from tabulate import tabulate
from dataclasses import dataclass
import yaml
from io import StringIO
import pprint


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    type: str
    locations: tuple


def flatten(nested):
    return list(chain.from_iterable(nested))


def load_grype_output(path):
    with open(path) as f:
        data = json.load(f)
    return data

def cve_key(match: dict) -> str:
    """
    Return the CVE-* id for this match if one exists (either as the native id
    or in relatedVulnerabilities), otherwise fall back to the native id.
    This is the grouping key — one entry per CVE.
    """
    native_id = match.get("vulnerability", {}).get("id", "UNKNOWN")
    if native_id.startswith("CVE-"):
        return native_id
    for rv in match.get("relatedVulnerabilities", []):
        if rv.get("id", "").startswith("CVE-"):
            return rv["id"]
    return native_id  # no CVE alias exists; use native id as key


def group_by_cve(matches):
    """
    Group critical matches. Returns a dict:
        key: CVE where available or native ID if missing.
        value: {native_ids: [], packages: [], ...}
    """
    groups = {}
    for m in matches:
        vuln = m.get("vulnerability", {})
        native = vuln.get("id", "UNKNOWN")
        severity = vuln.get("severity", "Unknown")
        if severity.lower() != "critical":
            continue

        key = cve_key(m)

        artifact = m.get("artifact", {})
        pkg = Package(
            name=artifact.get("name", "?"),
            version=artifact.get("version", "?"),
            type=artifact.get("type", "?"),
            locations=tuple(
                loc.get("path", "?") for loc in artifact.get("locations", [])
            ),
        )

        if key not in groups:
            fix_versions = vuln.get("fix", {}).get("versions", [])
            groups[key] = {
                "key": key,
                "severity": severity,
                "description": vuln.get("description", ""),
                "fix": ", ".join(fix_versions) if fix_versions else "none",
                "urls": vuln.get("urls", []),
                "native_ids": set(),
                "packages": set(),
            }

        # Collect every distinct native advisory ID seen for this CVE
        groups[key]["native_ids"].add(native)

        groups[key]["packages"].add(pkg)
    return groups

class SafeFixmeLoader(yaml.SafeLoader):
    """ Reads yaml, adds __fixme__ entries for elements preceeded by FIXME: comments """
    def __init__(self, stream):

        # Copy the entire stream into memory as a string
        raw_text = stream.read()
        
        # Build dict of FIXME comments by line number:
        self.fixmes = {}
        for lno0, line in enumerate(raw_text.splitlines()):
            if line.lstrip().startswith("#") and "FIXME:" in line:
                self.fixmes[lno0 + 1] = line

        # Give PyYAML a fresh stream copy to parse
        super().__init__(StringIO(raw_text))

    def construct_mapping(self, node, deep=False):
        mapping = super().construct_mapping(node, deep=deep)
        lno = node.start_mark.line + 1
        if lno - 1 in self.fixmes:
            mapping['__fixme__'] = self.fixmes[lno - 1]
        return mapping

def load_ignores(config_path):
    with open(config_path) as f:
        data = yaml.load(f, Loader=SafeFixmeLoader)
    all_ignores = set()
    fixme_ignores = set()
    for e in data.get("ignore", []):
        r = Rule(e)
        all_ignores.add(r)
        if '__fixme__' in e:
            fixme_ignores.add(r)
    return dict(all_ignores=all_ignores, fixme_ignores=fixme_ignores)

def find_used_ignores(grype_output):
    used_ignores = set()
    for e in grype_output.get("ignoredMatches", []):
        for d in e["appliedIgnoreRules"]:
            r = Rule(d)
        used_ignores.add(r)
    return used_ignores


class Rule:
    # TODO: DOCUMENT WHAT IT MATCHES ON!
    def __init__(self, d):
        self.d = d
        self._key = self.rule_toset(d)

    def __hash__(self):
        return hash(self._key)

    def __eq__(self, other):
        if not isinstance(other, Rule):
            return NotImplemented
        return self._key == other._key

    def __str__(self):
        return yaml.dump([dict((k, v) for (k, v) in self.d.items() if k != '__fixme__')]).strip()

    def __lt__(self, other):
        if not isinstance(other, Rule):
            return NotImplemented
        return self._key < other._key

    @classmethod
    def rule_toset(cls, d):
        vuln = d.get("vulerability", "")
        pkg = d.get("package", {})
        locn = pkg.get("location", "")
        name = pkg.get("name", "")
        return (vuln, locn or name)
    

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a Grype JSON output file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input", help="Path to grype json-format output")
    parser.add_argument("--config", "-c", help="Path to grype config file")
    args = parser.parse_args()

    output = load_grype_output(args.input)
    matches = output.get("matches", [])
    print(f"Loaded {len(matches)} vulnerability matches from {args.input}")

    if args.config is not None:
        
        ignores = load_ignores(args.config)

        print(f"Loaded {len(ignores["all_ignores"])} ignore rules including {len(ignores["fixme_ignores"])} tagged FIXME from {args.config}")
        
        used_ignores = find_used_ignores(output)
        unused_ignores = ignores["all_ignores"]  - used_ignores
        if unused_ignores:
            print()
            print(f"INFO: {len(unused_ignores)} ignore rules were not used:")
            for r in sorted(unused_ignores):
                print(r)
            print()

        used_fixme_ignores = used_ignores & ignores["fixme_ignores"]
        if used_fixme_ignores:
            print(f"WARNING: {len(used_fixme_ignores)} ignore rules tagged FIXME were used:")
            for r in sorted(used_fixme_ignores):
                print(r)
            print()
        
    # Find critical CVEs, deduplicating info
    critical = group_by_cve(matches)

    # Create output:
    if critical:
        print(f"ERROR: {len(critical)} critical vulnerabiliies were not ignored:\n")
        table = []
        for cve in critical:
            item = critical[cve]
            native_ids = "\n".join(critical[cve]["native_ids"])
            locations = "\n".join(sorted(flatten(p.locations for p in item["packages"])))
            entry = [cve, native_ids, locations]
            table.append(entry)
        print(tabulate(table, ["CVE", "Native IDs", "Locations"]))

        sys.exit(1)


if __name__ == "__main__":
    main()
