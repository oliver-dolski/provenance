# provenance

`provenance` is a supply-chain security scanner for software projects. It reads
a project's dependency manifests and lockfiles, builds a Software Bill of
Materials (SBOM), and checks each component for known vulnerabilities and
supply-chain risks - dependency confusion, typosquatting, and unpinned or
withdrawn versions. Every finding carries a stated reason and a reference, so a
reviewer can act on it without re-deriving it.

## What it does

- Parses dependency manifests and lockfiles into a normalized component graph.
- Emits an SBOM in a standard format (CycloneDX).
- Cross-references components against known-vulnerability data.
- Flags supply-chain risks: dependency confusion, typosquatting, unpinned or
  withdrawn dependencies.
- Maps each finding to relevant guidance (CRA obligations, SLSA levels).

## Boundaries

- It reads files. It does not install, build, or execute any project
  dependency, and it makes no change to the scanned project.
- Vulnerability data comes from public sources; the tool states which source
  and version each finding is based on.
- A finding is a signal for review, not a verdict. The reason and reference
  are always shown so the reviewer decides.

## Status

Early scaffold. The design and boundaries above are the target; the
implementation is in progress and not yet functional.

## License

Apache-2.0. See [LICENSE](LICENSE).
