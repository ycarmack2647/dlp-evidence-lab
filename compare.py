"""Compare completed baseline/hardened runs without treating unavailable calls as passes."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("hardened", type=Path)
    args = parser.parse_args()
    a = json.loads(args.baseline.read_text(encoding="utf-8"))
    b = json.loads(args.hardened.read_text(encoding="utf-8"))
    if a["mode"] != "baseline" or b["mode"] != "hardened":
        parser.error("Provide a baseline results.json first, then a hardened results.json")
    for key in ("dataset_sha256", "code_sha256", "requested_model", "observed_models", "generation"):
        if a[key] != b[key]:
            parser.error("Comparison inputs differ: " + key)
    if [r["id"] for r in a["cases"]] != [r["id"] for r in b["cases"]]:
        parser.error("Runs must include the same case IDs in the same order")
    am, bm = a["metrics"], b["metrics"]
    lines = ["# DLP Evidence Lab comparison", "", "| Measurement | Baseline | Hardened |", "|---|---|---|"]
    for key in ("total_cases", "completed_model_responses", "unavailable_model_responses",
                "accepted_drafts", "injection_cases_completed", "injection_cases_passing_all_checks",
                "median_completed_latency_seconds"):
        lines.append(f"| {key} | {am[key]} | {bm[key]} |")
    for key in sorted(set(am["checks_passed_over_completed"]) | set(bm["checks_passed_over_completed"])):
        lines.append(f"| {key} | {am['checks_passed_over_completed'].get(key, 'not measured')} | {bm['checks_passed_over_completed'].get(key, 'not measured')} |")
    lines.extend(["", "Checks are computed on raw model content before display filtering. Both modes use the same schema, rule policy, and output gate. Hardened mode adds boundary instructions and data minimization together, so this comparison cannot isolate either control's individual contribution.",
                  "", "These are synthetic fixtures, not production DLP precision/recall. Manually review accepted summaries for unsupported claims and unsafe recommendations. Zero failures on four attack cases does not establish prompt-injection immunity."])
    output = args.hardened.parent / "comparison.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print("\nSaved:", output.resolve())


if __name__ == "__main__":
    main()
