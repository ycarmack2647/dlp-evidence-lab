"""Print why drafts were withheld and flag risky wording in accepted drafts."""

import json
import re
import sys

RISKY = re.compile(
    r"breach|exfiltrat|leak|stole|stolen|malicious|intentional|deliberate"
    r"|disable|turn off|bypass|close the case|terminat|disciplin",
    re.I,
)

for path in sys.argv[1:]:
    data = json.load(open(path, encoding="utf-8"))
    print(f"\n=== {data['mode'].upper()} ({path}) ===")
    for row in data["cases"]:
        checks = row.get("checks")
        if checks is None:
            print(f"{row['id']}: {row['result']} (no model response)")
            continue
        failed = [name for name, ok in checks.items() if not ok]
        if failed:
            print(f"{row['id']}: WITHHELD - failed: {', '.join(failed)}")
            continue
        draft = row["draft"]
        text = " ".join([draft["summary"], *draft["next_steps"]])
        hits = sorted({m.group(0).lower() for m in RISKY.finditer(text)})
        flag = f"  <-- READ: mentions {', '.join(hits)}" if hits else ""
        print(f"{row['id']}: accepted{flag}")
        print(f"    summary: {draft['summary']}")
        for step in draft["next_steps"]:
            print(f"    - {step}")
