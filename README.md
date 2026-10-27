# DLP Evidence Lab

A two-day Python + local Qwen project: deterministic DLP triage, AI-generated investigation drafts, and prompt-injection evaluation.

**Start with `BUILD_GUIDE.md`** for the complete Windows walkthrough, learning exercises, troubleshooting, interview demo, and resume templates. `START_HERE.html` is a browser-friendly copy of that guide.

Requirements: Python 3.11+, LM Studio with a downloaded local model. No pip packages. Synthetic data only.

```powershell
python -m unittest -v
python lab.py --mode rules --out outputs/rules
python lab.py --list-models
$LabModel = 'PASTE-YOUR-EXACT-MODEL-ID-HERE'
python lab.py --mode hardened --model $LabModel --case DLP-001 --out outputs/first
```

Files:
- `engine.py`: policy, minimization, validation, output checks.
- `lab.py`: local API client, runner, metrics, escaped HTML report.
- `cases.json`: 12 hand-labeled synthetic cases, including 4 injection cases.
- `test_lab.py`: deterministic tests and fake HTTP integration.
- `compare.py`: matched baseline/hardened comparisons.
- `RESULTS_TEMPLATE.md`: your own measurements and manual-review record.
- `VALIDATION.md`: what was tested in the supplied starter; actual model results remain unmeasured.

The assistant never executes model output or takes enforcement actions. Passing automated checks does not establish semantic correctness or prompt-injection immunity.
