# provenance

`provenance` is a supply-chain security scanner for software projects. It reads
a project's dependency manifests and lockfiles, builds a Software Bill of
Materials (SBOM), and checks each component for known vulnerabilities and
supply-chain risks - dependency confusion, typosquatting, and unpinned or
unverified dependencies. Every finding carries a stated reason and a reference,
so a reviewer can act on it without re-deriving it.

```
$ provenance ./my-project
provenance 0.1.0
scanned     ./my-project
read        package-lock.json, requirements.txt

components  4  (npm 2, PyPI 2)
            4 direct, 0 indirect, 0 dev only, 0 unpinned

checked     4 of 4 components against OSV
            names compared against 125 known npm packages and 119 known PyPI
            packages

provenance  2 of 4 components carry verified build provenance
            2 publish none
            sigstore 3.0.0 built from
            https://github.com/sigstore/sigstore-js@3a57a741bfb9
            tuf-js 3.0.1 built from
            https://github.com/theupdateframework/tuf-js@18a6f58bbae7

findings    16  (2 critical, 6 high, 8 medium)

  CRITICAL lodash 4.17.11  (package-lock.json)
           vulnerability - Prototype Pollution in lodash
           OSV GHSA-jf85-cpcp-j695 (CVE-2019-10744)
           fixed in 4.17.12
           Versions of lodash before 4.17.12 are vulnerable to Prototype
           Pollution. The function defaultsDeep allows a malicious user to
           modify the prototype of Object...
           https://nvd.nist.gov/vuln/detail/CVE-2019-10744
           CRA Regulation (EU) 2024/2847, Annex I, Part II (2): in relation to
           the risks posed to products with digital elements, address and
           remediate vulnerabilities without delay, including by providing
           security updates; where technically feasible, new security updates
           shall be provided separately from functionality updates
```

## What it reads

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `package.json` |
| PyPI | `poetry.lock`, `requirements*.txt`, any `.txt` under `requirements/` |

Lockfiles are parsed before manifests: the lockfile states what is installed,
the manifest states what was asked for. Read in that order, a version range
annotates the resolved package instead of appearing as a second, versionless
copy of it. Installed-package directories (`node_modules`, `.venv`, `vendor`
and the like) are skipped - walking them would report the dependencies of
dependencies as if the project had declared them.

## What it checks

**Where the package came from.** npm publishes Sigstore bundles stating which
repository, which commit and which workflow produced a tarball. `provenance`
verifies them rather than displaying them:

1. The transparency log's signed entry timestamp is checked against Rekor's
   key, and the log entry's payload hash against the statement. The signing
   certificate is valid for ten minutes, so the signing time has to come from
   somewhere other than the bundle's own claim - and the payload hash is what
   stops a genuine timestamp being borrowed from a different entry.
2. The signing certificate is verified against vendored Fulcio roots **as of
   that time**, and the statement's repository is checked against the workflow
   identity in the certificate.
3. The DSSE signature is verified against the key the certificate binds.
4. The attested artifact digest is compared with the `integrity` hash in the
   lockfile. This is the step that turns a valid statement about *some* tarball
   into a statement about *the one this project installs*.

Trust roots are vendored rather than fetched: a root downloaded at scan time is
trusted on the strength of the connection that delivered it, which is what
signatures exist to stop relying on. Replacing them is a commit, visible in
this repository's history.

**Known vulnerabilities**, from [OSV](https://osv.dev), which aggregates the
advisory feeds of both ecosystems. Severity is computed from the published
CVSS v3 vector rather than taken from whichever word a database attached;
vectors of a version whose formulas are not implemented here are left unscored
instead of scored wrongly. Records that describe the same issue under different
identifiers are reported once, with every identifier kept.

**Supply-chain risks**, from the manifests alone, with no network call:

| Check | What it reports |
| --- | --- |
| unpinned | a dependency no lockfile resolves, so two builds of one commit can differ |
| private-source | a package fetched from somewhere other than the public registry, which is the precondition for dependency confusion |
| typosquat | a name one typo away from a widely used package |
| missing-integrity | a locked package with no hash, so a swapped artifact is not detected |
| provenance-failed | a published build attestation that does not survive verification |
| provenance-mismatch | an attestation that verifies, and covers a different artifact than the lockfile pins |

Packages that publish no attestation are counted rather than listed. Most still
publish none, and a finding each would bury everything else in the report.

Each finding is mapped to the obligation it engages: the CRA requirement to
inventory components and to remediate without delay, or the SLSA threat it
falls under. That is a pointer to the requirement, not a compliance verdict.

## Usage

```
provenance [flags] <project-path>

  -sbom <file>       write a CycloneDX SBOM to <file> ("-" for stdout)
  -format <format>   report format: text (default) or json
  -offline           skip every network lookup; run only the offline checks
  -attest=false      do not verify build provenance (it costs one registry
                     request per npm package)
  -fail-on <level>   exit 3 when a finding of this severity or higher is
                     reported: none (default), low, medium, high, critical
  -version           print version and exit
```

Exit codes: `0` success, `1` error, `2` usage, `3` findings at or above the
`-fail-on` threshold. Findings change the exit code only when asked for, so
adding this to a pipeline does not break the pipeline by surprise.

## Boundaries

- It reads files. It does not install, build, or execute any project
  dependency, and it makes no change to the scanned project.
- Vulnerability data comes from a public source; the report states which
  source, how many components were queried, and which ones could not be.
- A finding is a signal for review, not a verdict. The reason and reference are
  always shown so the reviewer decides.
- A scan that could not answer everything says so. An empty finding list and an
  unanswered question are not allowed to look alike.

## What it does not do

- It does not resolve version ranges. A dependency with no lockfile entry is
  reported as unpinned and is not queried for vulnerabilities, because matching
  a range against advisory ranges would be a guess presented as a result.
- Provenance verification checks the transparency log's signed entry timestamp,
  not the Merkle inclusion proof. That establishes that the log signed this
  entry at this time; it does not prove the entry is in the published tree.
- Only npm publishes attestations this tool reads. PyPI attestations (PEP 740)
  are not read yet, so a PyPI component is never reported as having verified
  provenance - which is a gap in the tool, not a statement about the package.
- Other ecosystems and lockfile formats - Go modules, Maven, `yarn.lock`,
  `pnpm-lock.yaml`, `Pipfile.lock` - are not read yet.
- The typosquatting check compares against a bundled list of a few hundred
  widely used names, and the report says how many. A name missing from that
  list is not thereby judged safe.
- It says nothing about how a dependency behaves at runtime.

## Building

Go 1.22 or later, and nothing else: the scanner has no third-party
dependencies, which is a property worth keeping in a tool whose subject is
dependencies.

```
go build ./cmd/provenance
go test ./...
```

## License

Apache-2.0. See [LICENSE](LICENSE).
