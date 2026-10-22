# Validation record

Package: PHP Skeptic 0.1.0
Research snapshot date: 2026-10-22

## Executed

`python3 -m unittest discover -s tests -v`

Result: **51 tests passed**. The raw output is in `TEST-RESULTS.txt`.

Tests exercised synthetic local fixtures and offline helper logic: conservative version hints; missing, empty, bounded, binary and compressed logs; secret/instruction non-disclosure in log summaries; regular-file constraints; final/parent symlink and FIFO rejection; filename-based project candidates; depth/entry/time limits; excluded directories; private report permissions; overwrite rejection; acknowledgment gates; helper CLI behavior; JSON and local Markdown link consistency.

## Not executed / not established

No scan of the user's server or projects. No live Apache, Nginx, LiteSpeed, OpenLiteSpeed, FPM, FrankenPHP, hosting panel, Windows/IIS or Kubernetes integration test. No production traffic, vulnerability exploitation, patch installation or restart. No automatic claim that the behavioral scenarios in `references/evaluation.md` pass; those require agent-level evaluation in authorized synthetic environments.

The helper tests do not prove that an agent will obey all instructions, that discovery is exhaustive, that log signatures detect exploitation, or that a deployment is secure. The supported stack coverage in the skill is runbook coverage; automated helper coverage is narrower and stated in the README.
