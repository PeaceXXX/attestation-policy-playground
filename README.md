# attestation-policy-playground

A Rego-inspired policy playground for attestation evidence, in Go
(stdlib only). Write a policy as a `.rego` file, feed it an attestation
evidence bundle as JSON, and get a verdict — allow or deny — with a
per-rule trace that says exactly which condition decided it.

## Why this exists

Attestation answers "is this workload what it claims to be?" — but the
answer is never just the quote. Somebody has to decide what counts as
good enough: which TCB version, how fresh the evidence must be, which
measurements are acceptable, whether a GPU claim is bound to the same
job as the CPU claim. That decision lives in **policy**, and in real
systems (Intel Trust Authority included) policy is the layer operators
actually argue about, break, and get paged for.

The trigger for building it now is a live one in the confidential
computing sphere: Ronghua Yu's recent post — "an essential policy every
agent sandbox should have" — put policy at the centre of the agent
sandbox conversation, while the ddrop freshness debate and the SGX
retirement (Diamond Rapids is the last Xeon with SGX) keep raising the
same question from two sides: *what evidence do we still trust, and for
how long?* A policy playground is the smallest honest demo of that
decision layer: no real quotes, no real verifier, just the logic of
"given this evidence, would you let this workload in?"

> **Clean-room statement.** All concepts here are public and general
> engineering: Rego-style policy rules, JSON evidence bundles, and
> allow/deny evaluation with default deny. No Intel-internal code, APIs,
> or non-public details are used or implied, and no real attestation
> evidence is processed. Every measurement, SVN, and nonce in the
> examples is invented sample data.

## Architecture

```
                +------------------+        +------------------+
                |  operator        |        |  browser         |
                |  policycheck CLI |        |  playground UI   |
                +--------+---------+        +--------+---------+
                         |                           |
                         v                           v
                +--------+---------+        +--------+---------+
                | internal/policy  |<-------| internal/server  |
                |  .rego parser    |  JSON  |  HTTP API + UI   |
                |  evaluator       |  API   |  (embedded)      |
                |  default deny /  |        +------------------+
                |  deny-wins       |
                +--------+---------+
                         |
              +----------+-----------+
              | policies/*.rego      |
              | examples/evidence/*  |
              +----------------------+
```

Evaluation semantics, the three rules that matter:

1. **Default deny.** If no allow rule matches, the workload is denied.
2. **Deny wins.** If any deny rule fires, the verdict is deny even when
   an allow rule also matched. Explicit denials are never outvoted.
3. **Fail closed on the unknown.** A policy file the parser cannot
   understand is rejected with an error at load time; it never silently
   admits (or rejects) a workload.

## Quickstart

```bash
go test ./...          # unit + HTTP tests (verified live)
make build             # builds bin/playground and bin/policycheck

# CLI: evaluate one evidence bundle against one policy.
# Exit code: 0 = allowed, 1 = denied, 2 = usage / parse error.
./bin/policycheck -policy policies/strict.rego \
  -evidence examples/evidence/good-tdx.json
./bin/policycheck -policy policies/strict.rego \
  -evidence examples/evidence/stale-evidence.json -trace

# Web UI + JSON API on :8080 (or PLAYGROUND_ADDR=:9090 ./bin/playground)
./bin/playground
# then open http://localhost:8080

# Docker
docker build -t attestation-policy-playground .
docker run -p 8080:8080 attestation-policy-playground
```

Try the interesting pairs:

| Policy | Evidence | Verdict | Why |
| --- | --- | --- | --- |
| `strict.rego` | `good-tdx.json` | ALLOW | current TCB, fresh evidence |
| `strict.rego` | `stale-evidence.json` | DENY | evidence is 3600s old (> 300s) |
| `strict.rego` | `old-tcb.json` | DENY | TCB SVN 2 < 5, status out_of_date |
| `strict.rego` | `sgx-legacy.json` | DENY | platform is SGX, policy wants TDX |
| `strict.rego` | `zero-mrtd.json` | DENY | MRTD is all zeros (never populated) |
| `gpu-workload.rego` | `good-tdx.json` | ALLOW | CPU + GPU claims bound to job-8842 |
| `gpu-workload.rego` | `gpu-job-mismatch.json` | DENY | GPU claim bound to job-9999, workload to job-8842 |
| `standard.rego` | `sgx-legacy.json` | DENY | platform not in [tdx, sev-snp] |
| `dev.rego` | any bundled evidence | DENY | all bundled evidence is `environment: prod` |

## The policy language (a Rego subset)

Policies are real `.rego` files using the constructs the parser
understands. Anything outside the subset is a parse error, not a silent
mis-evaluation.

```rego
package attestation

default allow = false

allow if {
    input.platform == "tdx"
    input.tcb.svn >= 5
    input.evidence.age_seconds < 300
    input.platform in ["tdx", "sev-snp"]
    count(input.measurements.allowed) >= 1
    startswith(input.workload.image, "ghcr.io/peacexxx/")
    input.gpu.job_id == input.workload.job_id
}

deny["TCB SVN is below the minimum (5)"] if {
    input.tcb.svn < 5
}

deny[msg] if {
    input.measurements.mrtd == "0000000000000000000000000000000000000000000000000000000000000000"
    msg := "MRTD is all zeros; the measurement was never populated"
}
```

Supported, per condition line: comparisons (`== != >= <= > <`),
membership (`in [...]`, `not in [...]`), `count(path)` comparisons,
`startswith` / `endswith` / `contains`, field-to-field comparison
(`input.gpu.job_id == input.workload.job_id`, used to bind a GPU claim
to a workload), `not` negation, and bare-path truthiness checks. Paths
use `input.` plus dotted fields with optional `[n]` indexing
(`input.measurements.list[1].value`).

Bundled policies:

- `strict.rego` — production TDX: SVN >= 5, status up_to_date, evidence
  < 300s, non-zero MRTD, debug forbidden.
- `standard.rego` — TDX or SEV-SNP, SVN >= 3, evidence < 900s.
- `dev.rego` — admits only `environment: "dev"`; never use outside a
  sandbox.
- `gpu-workload.rego` — composite CPU + GPU attestation: both claims
  present, current, and bound to the same `job_id`, image from the
  trusted registry.

## API reference

Base URL: `http://localhost:8080`

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Web UI (pick policy + evidence, evaluate, inspect the trace) |
| `GET` | `/api/policies` | List bundled policies (`name`, `title`, `rules`) |
| `GET` | `/api/policies?name=strict.rego` | Raw policy source |
| `GET` | `/api/evidence` | List bundled evidence bundles with their JSON |
| `POST` | `/api/evaluate` | `{"policy": "strict.rego", "evidence": {...}}` → verdict |

`POST /api/evaluate` response:

```json
{
  "allowed": false,
  "policy": "strict.rego",
  "reasons": ["evidence is stale: older than 300 seconds"],
  "trace": [
    {
      "rule_id": "allow-1",
      "effect": "allow",
      "fired": false,
      "conditions": [
        {"condition": "input.evidence.age_seconds < 300", "passed": false,
         "detail": "input.evidence.age_seconds = 3600, want < 300"}
      ]
    }
  ]
}
```

## What this demonstrates

- **Policy-as-decision-layer thinking.** The demo separates *evidence*
  (what a quote claims) from *policy* (what the operator accepts) — the
  same split a Trust Authority-style verifier makes, and the first thing
  an interviewer probes when you say "I built attestation tooling".
- **Fail-closed design.** Default deny, deny-wins, and a parser that
  rejects unknown syntax instead of guessing. Security code that fails
  open is the classic interview trap; this codebase is built to be
  questioned on it.
- **A real parser and evaluator in stdlib Go.** Tokenizer, rule parser,
  path resolver with indexing, numeric/string/bool comparison, and a
  per-condition trace — no dependencies, `go vet` + `go test` clean.
- **Composite attestation, concretely.** The GPU policy shows the
  binding problem in six lines: two independent claims are only useful
  together when they name the same job. That is the whole idea of the
  earlier `composite-attestation-combiner` project, expressed as policy.
- **Operability.** Two interfaces (CLI for scripts/CI, HTTP + UI for
  humans), exit codes a pipeline can branch on, and a Dockerfile that
  runs the tests before it builds the image.

## Limitations / how I'd productionize it

- **This is a Rego subset, not OPA.** Real deployments should evaluate
  policies with OPA itself (or Rego compiled to Wasm) instead of a
  hand-rolled parser; the subset exists to make the *semantics*
  inspectable in one sitting. The bundled `.rego` files are written to
  stay close to valid Rego so migrating them to OPA is mechanical.
- **No real verification.** Evidence here is trusted JSON. A production
  verifier must check the quote signature, the collateral chain, and the
  nonce binding before policy ever runs — policy is the last gate, not
  the only one.
- **No policy versioning or signing.** Policies are files on disk. In
  production they need versioning, review, and signatures, because a
  silently edited policy is a silently widened trust boundary.
- **In-memory, single process.** No persistence, no audit log, no auth
  on the API. The sibling project `attestation-key-rotation` shows the
  audit-log half of this story (hash-chained lifecycle events).
- **Freshness is wall-clock age.** Real freshness needs the verifier's
  own timestamp at receipt plus a nonce challenge, not a field the
  workload reports about itself.
