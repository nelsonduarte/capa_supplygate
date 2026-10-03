#!/bin/sh
# Regenerate the SupplyGate machine-verifiable artefacts:
#
#   out/report.txt          the human gate report for the realistic build (FAIL)
#   out/gate.json           the machine gate decision for that build
#   out/report_clean.txt    the human gate report for the remediated build (PASS)
#   out/gate_clean.json     the machine gate decision for that build
#   sbom/manifest.json      the capability manifest (surface + declassify sites)
#   sbom/sbom.cyclonedx.json  CycloneDX 1.5 SBOM with the manifest embedded
#   sbom/sbom.spdx.json       SPDX 2.3 SBOM companion
#   sbom/provenance.slsa.json SLSA build provenance
#
# The reports and gate decisions are produced by RUNNING SupplyGate; the
# SBOM family is EMITTED BY THE COMPILER from the same source. Together they
# are the evidence: SupplyGate states the verdict, and the compiler records
# the tool's own surface (main declares Fs and Stdio, no Net) and checks the
# flows of its @secret feed credential.
#
# Determinism comes from SOURCE_DATE_EPOCH (reproducible-builds.org): the
# compiler stamps the SBOM build time from this fixed instant. The
# compiler's tests pin byte-identical output for repeated runs; a
# rebuild-and-diff is a check to run, not a guarantee. Bump it by writing a new UTC epoch to
# sbom/SOURCE_DATE_EPOCH and rerunning this script.
#
# Run every Capa invocation through the LOCAL compiler:
#     python -m capa ...   (from a checkout of the Capa compiler)
# The examples below assume `capa` resolves to that build.
set -e

SOURCE_DATE_EPOCH="$(tr -d '\r' < sbom/SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH

mkdir -p out sbom

# Run the gate (Python backend) to produce the reports + gate decisions.
capa --run supplygate.capa

# Emit the compiler-side proof artefacts.
capa --manifest   supplygate.capa > sbom/manifest.json
capa --cyclonedx  supplygate.capa > sbom/sbom.cyclonedx.json
capa --spdx       supplygate.capa > sbom/sbom.spdx.json
capa --provenance supplygate.capa > sbom/provenance.slsa.json

echo "regenerated out/ and sbom/ (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
