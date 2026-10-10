# haruspex threat model

## Role

The reverse-engineering organ of a sovereign agent: reads binaries on
the machine it lives on. Designed for inspection and audit, not
exploitation.

## Trust boundaries

- The *target file* is untrusted input. Parsing is bounds-checked
  everywhere; malformed input yields `Error`, never a panic, never an
  out-of-bounds read.
- The *report* is evidence, not verdict. A caller deciding policy on
  flags alone is misusing the tool — flags name observations with
  offsets, a reviewer checks them.
- The crate is read-only by construction: no `Command`, no `dlopen`,
  no network. It cannot execute what it inspects.

## What it deliberately does not do

- No write or patch operations.
- No symbolication services, no crash-report upload, no telemetry.
- Does not follow rpaths or resolve dyld — it reports what the file
  declares, which is exactly what an auditor wants to see.

## Residual risks

- Heuristic flags can both miss (a binary that embeds a URL
  non-contiguously) and over-report (substring API matches). Evidence
  offsets are the mitigation.
- Stripped binaries yield fewer findings; that is reported as absence
  of evidence, not evidence of innocence.
