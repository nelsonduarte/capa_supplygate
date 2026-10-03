# SupplyGate

A supply-chain **compliance gate for CI/CD** that decides **PASS or FAIL**
for a build and emits its **own capability SBOM as evidence**. SupplyGate reads
a project's SBOM, an offline vulnerability feed and your organisation's
policy, cross-references them, and produces a machine-readable gate decision
your pipeline can block on. It then shows, with a compiler-emitted SBOM,
which capabilities it holds: `Fs` and `Stdio`, and no `Net`.

The evidence is not a policy document or a code-review sign-off. It is the
output of a compiler: the [Capa](https://github.com/nelsonduarte)
information-flow check reports a path it detects from the tool's own
credentials to an output, and reports none for this program, and the
capability SBOM Capa emits lists the capabilities the tool holds
(`{Fs, Stdio}`, and no `Net`).

## The problem

Procurement, the EU Cyber Resilience Act (CRA) and NIS2 all push the same
requirement onto software suppliers: before a build ships, show that its
dependencies are free of known-exploited vulnerabilities above an agreed
severity, carry acceptable licences, contain no banned components, and pin
the versions you promised. Most teams bolt this onto CI with a pile of
scanners whose own trust story is an afterthought: the gate tool itself
reads every project's SBOM and often holds a feed credential, yet nothing
proves that tool cannot leak what it sees or phone home.

SupplyGate shows a different model. The gate decision is real (it evaluates
four policy rules against a vulnerability feed), and the **gate tool's own
authority is machine-checked**: the information-flow check reports no
flow from its feed credential to an output, and no function in the tool
holds `Net` (capability discipline). Both results come from
the compiler, and the capability side ships as an SBOM an auditor can
regenerate.

## What SupplyGate does

Given three local inputs, it evaluates a build against the organisation
policy and decides the gate:

1. **Parses the project SBOM** (CycloneDX 1.5 JSON) into typed components
   (name, version, purl, licence).
2. **Parses the vulnerability feed** (an offline OSV-style JSON export) into
   typed advisories with severity and CVSS.
3. **Parses the policy** (allowed / denied licences, maximum tolerated CVSS,
   banned packages, required version pins).
4. **Cross-references and evaluates** four independent rules per component:
   - *vulnerability*: a version-matched advisory whose CVSS exceeds the
     policy ceiling;
   - *license*: a licence on the deny list, or off the allow list;
   - *banned*: an explicitly banned package;
   - *pin*: a policy-pinned package present at the wrong version.
5. **Decides PASS/FAIL** and writes two artefacts: a human report
   (`out/report.txt`) and a machine gate decision (`out/gate.json`,
   `{"gate": "pass|fail", "violations": [...]}`) for the CI step to block on.

To make both verdicts visible in one reproducible run, SupplyGate evaluates
two projects against the same policy: a realistic build that **FAILS** and a
remediated build that **PASSES**.

### The gate decision, machine-readable

```json
{
  "gate": "fail",
  "passed": false,
  "project": "acme-checkout-service@2.4.0",
  "component_count": 12,
  "violation_count": 5,
  "violations": [
    { "rule": "vulnerability", "component": "pyyaml@5.3",
      "detail": "GHSA-mock-yaml-4410 (CRITICAL, CVSS 9.8) exceeds policy ceiling CVSS 7.0: ..." },
    { "rule": "banned", "component": "event-stream@3.3.6",
      "detail": "package 'event-stream' is explicitly banned by policy" },
    { "rule": "license", "component": "vendor-analytics@0.9.2",
      "detail": "licence 'GPL-3.0-only' is on the policy deny list" }
  ]
}
```

A CI step gates on `passed`. The remediated build produces
`{"gate": "pass", "violation_count": 0, "violations": []}`.

The matching is version-aware and conservative: `urllib3@1.26.5` carries an
advisory at CVSS 6.5, which is **below** the 7.0 ceiling and does not fire;
`lodash@4.17.19` has an advisory that affects only older versions and does
not fire. Only genuine, policy-exceeding findings fail the gate.

## What the compiler checks about the tool itself

Two independent compiler checks, plus the SBOM that records the capability
side.

### 1. Information-flow control: the credential is under the check

SupplyGate models an authenticated vulnerability feed, so it holds a bearer
token. That token is `@secret`:

```capa
pub type FeedCredential {
    token: @secret String
}
```

From any read of `creds.token`, the compiler propagates a confidentiality
label and reports a flow it detects to a public sink (the gate report, the
gate JSON, the console) that does not pass through an audited `declassify`.
SupplyGate never declassifies it, and the check reports no such flow in
`supplygate.capa`. `leaky_supplygate.capa` is the counter-example that makes
this concrete: it deliberately tries to write, print and log the token
under `@strict_ifc`, and the compiler refuses it:

```
$ python -m capa --check leaky_supplygate.capa
leaky_supplygate.capa:33:37: error: information-flow: a @secret value reaches
  Fs.write (argument 2), a public sink ...
leaky_supplygate.capa:42:38: error: information-flow: a @secret value reaches
  Fs.write (argument 2), a public sink ...
leaky_supplygate.capa:50:19: error: information-flow: a @secret value reaches
  Stdio.println (argument 1), a public sink ...
leaky_supplygate.capa:58:18: error: information-flow: a @secret value is passed
  to 'StdioLogger.error' as message, which reaches a public sink ...
leaky_supplygate.capa: 4 errors            # exit code 1
```

The fourth error is the important one: routing the secret through the
`capa_log` logger does not launder it. The flow to the underlying public
sink is still rejected. The real gate (`supplygate.capa`) checks clean.

### 2. Capability discipline: the gate holds no `Net`

`main` acquires exactly two capabilities, `Fs` and `Stdio`, and immediately
splits the filesystem authority into a **read-only view over `data/`** and a
**write view over `out/`**. It never acquires `Net`, `Env`, `Proc`, `Db`,
`Clock`, `Random` or `Unsafe`. The compiler checks it, and the SBOM records
it:

```
$ python -m capa --manifest supplygate.capa \
    | jq '.functions[] | select(.source_name=="main")
          | {declared: .declared_capabilities, excluded: .provably_excluded_capabilities}'
{
  "declared": ["Stdio", "Fs"],
  "excluded": ["Clock", "Db", "Env", "Logger", "Net", "Proc", "Random", "Unsafe"]
}
```

"This gate cannot phone home" is therefore a checked fact, not a promise:
with no `Net` capability anywhere in the program, there is no code path that
reaches the network. Its only mention in the SBOM is
`capa:provably_excluded_capability = Net`.

### 3. The artefacts: gate decision + SBOM

`./generate.sh` produces, with timestamps pinned by `SOURCE_DATE_EPOCH`:

| Artefact | Emitted by | What it shows |
| --- | --- | --- |
| `out/report.txt` / `out/gate.json` | running SupplyGate | the FAIL verdict + violations |
| `out/report_clean.txt` / `out/gate_clean.json` | running SupplyGate | the PASS verdict |
| `sbom/manifest.json` | `capa --manifest` | the capability surface + 0 declassify sites |
| `sbom/sbom.cyclonedx.json` | `capa --cyclonedx` | CycloneDX 1.5 SBOM (Dependency-Track, syft) |
| `sbom/sbom.spdx.json` | `capa --spdx` | SPDX 2.3 companion (OpenChain pipelines) |
| `sbom/provenance.slsa.json` | `capa --provenance` | SLSA build provenance over the source |

The manifest shows **zero declassification sites**: the tool makes no
deliberate disclosure of anything derived from its secret. The gate decision
is SupplyGate's verdict; the SBOM is the compiler's record of SupplyGate
itself. A supply-chain tool that ships its own compiler-derived SBOM is the
meta-message.

## Layout

| Path | Role |
| --- | --- |
| `domain.capa` | the typed vocabulary: components, advisories, policy, decision |
| `jsonx.capa` | small total extraction helpers over the built-in JSON tree |
| `ingest.capa` | CycloneDX SBOM parse into typed components (no capability) |
| `feed.capa` | OSV export parse + the `@secret` feed credential (no capability) |
| `policy.capa` | organisation policy parse (no capability) |
| `eval.capa` | the gate engine: cross-reference + four policy rules (no capability) |
| `report.capa` | build the human report + machine gate JSON (no capability) |
| `supplygate.capa` | the orchestrator: read (Fs ro) -> evaluate -> write (Fs wo) |
| `leaky_supplygate.capa` | counter-example: the credential leak the compiler rejects |
| `data/project.cdx.json` | sample failing build SBOM (12 components) |
| `data/project_clean.cdx.json` | sample remediated build SBOM (6 components) |
| `data/osv.json` | sample offline OSV vulnerability export |
| `data/policy.json` | sample organisation policy |
| `out/` | sample generated reports + gate decisions |
| `sbom/` | sample generated manifest + SBOMs + provenance |
| `capa_log` (git dep) | holds only the `Stdio` its caller hands it; fetched + GPG/SLSA-verified by `capa install` into `vendor/` (the CI audit log) |

## Run it

All commands use the local Capa compiler; substitute `python -m capa` for
`capa` if the installed `capa` is not the build you intend.

```sh
# One-time: fetch + verify the git dependency (needs capa >= 1.15.1).
# `capa install` clones capa_log at its signed tag, verifies the tag's
# GPG signature against the verify_key in capa.toml and its SLSA
# provenance, writes capa.lock, and vendors the source under vendor/.
# Import the publisher key first (see capa_log's SECURITY.md). capa_log
# holds only the Stdio it is handed, so this adds a verified supply
# chain without widening the {Fs, Stdio} surface.
capa install

# Type-check + information-flow check (clean: no finding)
capa --check supplygate.capa

# Run the gate. Writes out/report.txt, out/gate.json and the clean pair.
capa --run supplygate.capa

# See the information-flow checker reject a deliberate credential leak
capa --check leaky_supplygate.capa       # 4 errors, exit code 1

# Regenerate the reports, gate decisions and the full SBOM family
./generate.sh
```

### Same source, four backends

SupplyGate runs unchanged on the Python backend, the core Wasm backend, as a
Wasm component, and as a stock WASI Preview 2 component. The reports and gate
JSON are **byte-identical** between the Python and Wasm backends (the WASI
component differs only in newline style, LF vs the platform newline).

```sh
capa --run supplygate.capa                            # Python
capa --wasm --run supplygate.capa                     # core Wasm, identical output
capa --wasm --component --run supplygate.capa         # Wasm component
capa --wasm --component --wasi --run supplygate.capa  # stock WASI Preview 2
```

The WASI run needs **no `--preopen`**: every filesystem path in the program
is a string literal at its `Fs` sink (`"data/osv.json"`, `"out/gate.json"`,
...), which the compiler resolves by constant propagation, so the
component's filesystem authority is fixed at compile time rather than granted
by the operator. The current WASI increment (b1) supports a **single**
`--preopen` for dynamic (non-literal) `Fs` paths; SupplyGate needs none, but
you can still pass one to preopen a directory explicitly:

```sh
capa --wasm --component --wasi --preopen data/:ro --run supplygate.capa
```

## Dependencies

One dependency, which **holds no capability of its own**, resolved as a
**verified git dependency** in `capa.toml`:

- `capa_log` - levelled logging over `Stdio` (the CI audit log lines).

It is pinned to a **GPG-signed release tag** with the publisher's
`verify_key`. `capa install` (needs `capa >= 1.15.1`) fetches it at that
tag, verifies the tag's **GPG signature** against `verify_key` and its
**SLSA build provenance** (via `gh attestation verify` against the public
Sigstore log), records the resolved commit SHA in `capa.lock`, and vendors
the source under `vendor/` (git-ignored, not committed). A force-pushed
tag or a substituted commit is rejected before the code is ever compiled.

```toml
[dependencies.capa_log]
git = "https://github.com/nelsonduarte/capa_log"
tag = "v0.1.2"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

This is the verifiable supply chain Capa is about, made concrete: the
dependency is not trusted by convention, it is **cryptographically verified
at install time**, and its pinned, signed provenance is recorded in
`capa.lock`. It holds no authority of its own, so the SupplyGate capability
surface stays `{Fs, Stdio}`, and the SBOM shows it does not widen
it. The SBOM/OSV/policy inputs are parsed with Capa's built-in JSON
support, so no parser dependency is needed.

## Beyond v1 (documented, not shipped)

A live authenticated OSV fetch over an attenuated `Net` capability
restricted to an allow-listed feed host is the natural v2 extension:
SupplyGate would then present the `@secret` credential to one allow-listed
host, and the same checks would apply to the credential's flow to that host
and to the gate outputs. It is left out of v1 to keep the capability surface at
`{Fs, Stdio}` and the offline run byte-reproducible; the feed is a local
`osv.json` and the credential is modelled as a held secret.

## Licence

MIT. See `LICENSE`. The sample SBOMs, vulnerability feed and policy are
entirely fictitious; the advisory ids are mock (`GHSA-mock-*`).
