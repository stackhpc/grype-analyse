# grype-analyse

Analyse [Grype](https://oss.anchore.com/docs/guides/vulnerability/) vulnerability scan output to help investigation of critical vulnerabilities
and manage Grype ignore rules.

The `grype-analyse` tool takes Grype json output and (optionally) the
Grype configuration used for the scan and outputs:

    - INFO messages for any ignore rules in the configuration which did not
      match any vulnerabilities, i.e. rules which should maybe be deleted.
    - WARNING messages for any ignore rules with "FIXME:" comments in the
      configuration which did match vulnerabilities, i.e. vulnerabilities
      which need fixing.
    - ERROR messages for any critical vulnerabilities which are not ignored,
      with a summary of CVE number (where present), "native" IDs and locations
      with matches.

So a [Grype configuration](https://oss.anchore.com/docs/reference/grype/configuration/)
like this:

```yaml
ignore:
    - vulnerability: CVE-2025-68121
        package:
        location: /usr/bin/ondemand_exporter
    ...
    # FIXME:
  - vulnerability: CVE-2026-27143
    ...
```
Might produce output like this:

```
INFO: 1 ignore rules were not used:
- vulnerability: CVE-2025-68121
  package:
    location: /usr/bin/ondemand_exporter

WARNING: 1 ignore rules tagged FIXME were used:
- vulnerability: CVE-2026-27143

ERROR: 1 critical vulnerabiliies were not ignored:

CVE             Native IDs    Locations
--------------  ------------  --------------------------
CVE-2026-39821  GO-2026-5026  /usr/bin/apptainer
                              /usr/bin/ondemand_exporter
```

## Usage

- Install via pip/uv.
- Run a Grype scan should have been run using json-format output, e.g.

    ```shell
    grype -c ./.grype.yaml --only-fixed "sbom:myimg-sbom.syft-json" -o json > grype.out.json
    ```
- Run `grype-analyse` passing same Grype configuration file used for the scan:

    ```shell
    grype-analyse -c ./.grype.yaml grype.out.json
    ```

    Note that if the `-c` option is not passed to `grype-analyse` it will not
    load configuration and cannot analyse ignore rules. This is different from
    `grype` itself where it will load configuration at the default location, if
    present.

## Ignore rules

Ignore rules in configuration and scan output are considered to match based on
only the following fields - all others are ignored:
    - `vulnerability`
    - `package.location` or `package.name`

Ignore rules can be marked as "FIXME" rules by adding a comment on the line
immediately preceeding the element in the `ignore` configuration key. The line
must have `#` as the first non-whitespace character and must contain "FIXME:".
See example above.
