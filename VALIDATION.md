# Starter validation

Validated in the authoring environment on 2026-10-25.

- 15 Python unittest tests passed.
- All 12 hand-labeled rule fixtures matched.
- Rules-only command generated JSON and escaped HTML reports.
- A temporary fake local HTTP server exercised both evaluation modes and the comparison command end to end. A deliberate canary echo was measured before filtering, and its draft was withheld.
- An unavailable local server produced a visible error, zero completed model responses, and retained deterministic evidence.

These tests validate software behavior with fixtures and stubs. They are NOT Qwen evaluations, production security validation, Windows ARM64 runtime testing, or proof of prompt-injection resistance. The live LM Studio/Qwen call must be run on your laptop. No fabricated model performance numbers are included.
