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
from tabulate import tabulate
from dataclasses import dataclass
import yaml
from io import StringIO
import os
import requests

@dataclass(frozen=True)
class Package:
    name: str
    version: str
    type: str


# Package types where the location is the package database, not the package:
OS_PACKAGE_TYPES = {"rpm", "deb", "apk", "alpm", "portage"}


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
        value: {native_ids: set, packages: {Package: {native_ids: set, locations: set}}, ...}
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
        )

        if key not in groups:
            groups[key] = {
                "key": key,
                "severity": severity,
                "description": vuln.get("description", ""),
                "urls": vuln.get("urls", []),
                "native_ids": set(),
                "packages": {},
            }

        # Collect every distinct native advisory ID seen for this CVE
        groups[key]["native_ids"].add(native)

        # Collect native IDs and locations per package, so e.g. the same Go
        # stdlib version in several binaries is reported once:
        pkg_info = groups[key]["packages"].setdefault(pkg, {"native_ids": set(), "locations": set()})
        pkg_info["native_ids"].add(native)
        pkg_info["locations"].update(
            loc.get("path", "?") for loc in artifact.get("locations", [])
        )
    return groups

def suggest_ignore_rules(critical):
    """ Return yaml text for ignore rules which would suppress the given critical vulnerabilities.
        OS packages are matched by name, as their location is the package database,
        others by location.
    """
    lines = []
    seen = set()
    for item in critical.values():
        for pkg, info in item["packages"].items():
            comment = f"# FIXME: {pkg.name} {pkg.version}"
            for native in sorted(info["native_ids"]):
                if pkg.type in OS_PACKAGE_TYPES:
                    packages = [{"name": pkg.name}]
                else:
                    packages = [{"location": loc} for loc in sorted(info["locations"])]
                for package in packages:
                    rule = {"vulnerability": native, "package": package}
                    rule_key = Rule(rule)
                    if rule_key in seen:
                        continue
                    seen.add(rule_key)
                    lines.append(comment)
                    lines.append(yaml.dump([rule], sort_keys=False).strip())
    return "\n".join(lines)

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
            used_ignores.add(Rule(d))
    return used_ignores


class Rule:
    """ A representation of a Grype ignore rule which can be used as a set element.
        Only fields `vulnerability`, `package.location` and `package.name` are
        considered when hashing.
    """
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
        """ Return something like the original yaml rule definition """
        return yaml.dump([dict((k, v) for (k, v) in self.d.items() if k != '__fixme__')]).strip()

    def __lt__(self, other):
        if not isinstance(other, Rule):
            return NotImplemented
        return self._key < other._key

    @classmethod
    def rule_toset(cls, d):
        vuln = d.get("vulnerability", "")
        pkg = d.get("package", {})
        locn = pkg.get("location", "")
        name = pkg.get("name", "")
        return (vuln, locn or name)
    
def check_run(name, comment, conclusion, matrix=None):
    # conclusion: action_required,failure,neutral,success
    url = f"{os.environ['GITHUB_API_URL']}/repos/{os.environ['GITHUB_REPOSITORY']}/check-runs"
    headers = {
        "Authorization": f"token {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json",
    }
    json = {
        "name": f"[{matrix}] {name}" if matrix else name,
        "head_sha": os.environ["GITHUB_SHA"],
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": comment,
            "summary": comment,
        },
    }
    if os.environ.get('DEBUG'):
        print(dict(url=url, headers=headers, json=json))
    else:
        response = requests.post(url, headers=headers, json=json)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            print(response.json())
            raise

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a Grype JSON output file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input", help="Path to grype json-format output")
    parser.add_argument("--config", "-c", help="Path to grype config file")
    parser.add_argument("--github-checks", "-g", help="Create GitHub check-runs", action="store_true")
    args = parser.parse_args()
    matrix = os.environ.get('GRYPE_ANALYSE_MATRIX')

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
        print(f"ERROR: {len(critical)} critical vulnerabilies were not ignored:\n")
        table = []
        for cve in critical:
            item = critical[cve]
            for i, (pkg, info) in enumerate(item["packages"].items()):
                native_ids = "\n".join(sorted(info["native_ids"]))
                if pkg.type in OS_PACKAGE_TYPES:
                    locations = f"({pkg.type})"
                else:
                    locations = "\n".join(sorted(info["locations"]))
                entry = [cve if i == 0 else "", native_ids, f"{pkg.name} {pkg.version}", locations]
                table.append(entry)
        print(tabulate(table, ["CVE", "Native IDs", "Package", "Locations"]))
        print()
        print("Suggested ignore rules IF review shows they can be suppressed:\n")
        print(suggest_ignore_rules(critical))
    
    # Set GitHub check run status:
    if args.github_checks and args.config is not None:
        check_run(
            "Grype: Unused ignore rules",
            f"{len(unused_ignores)} unused ignore rules",
            "neutral" if unused_ignores else "success",
            matrix
        )
        check_run(
            "Grype: FIXME ignore rules",
            f"{len(used_fixme_ignores)} ignore rules tagged FIXME used",
            "neutral" if used_fixme_ignores else "success",
            matrix
        )
    if args.github_checks:
        check_run(
            "Grype: Critical vulnerabilities",
            f"{len(critical)} critical vulnerabilities were not ignored",
            "failure" if critical else "success",
            matrix
        )

    # Fail workflow if un-ignored critical:
    if critical:
        sys.exit(1)

if __name__ == "__main__":
    main()
