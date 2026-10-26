#!/usr/bin/env python3
"""Inventory bridge.go against Rust handlers at the pinned upstream revision.

This checks names, not semantics; guest fixtures must test behavior separately.
The Go checkout is only an audit input, never a build/runtime dependency.
"""
import argparse
import pathlib
import re
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("go_repo", type=pathlib.Path)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
revision = re.search(r'UPSTREAM_REVISION: &str = "([0-9a-f]+)"',
                     (root / "src/store/mod.rs").read_text()).group(1)
source = subprocess.check_output(
    ["git", "-C", str(args.go_repo), "show",
     f"{revision}:internal/store/emulator/bridge.go"], text=True)
symbols, messages = source.split("func (r *Runtime) message", 1)
messages = messages.split("func (r *Runtime) responds", 1)[0]
rust = "\n".join(p.read_text().split("#[cfg(test)]", 1)[0]
                 for p in (root / "src/store/runtime").glob("*.rs")
                 if not p.name.endswith("_tests.rs"))
groups = {"symbols": re.findall(r'^\tcase (.+):$', symbols, re.M),
          "selectors": re.findall(r'^\t{1,2}case (.+):$', messages, re.M)}
missing = []
for kind, cases in groups.items():
    names = sorted({name for case in cases for name in re.findall(r'"([^"]+)"', case)})
    for name in names:
        # Store dispatch normalizes imported C symbols by stripping underscores.
        normalized = name.lstrip("_") if kind == "symbols" else name
        if f'"{normalized}"' not in rust:
            missing.append(f"{kind}: {name}")
    print(f"{kind}: {len(names)} upstream case labels checked")
print(f"reference: {revision}")
if missing:
    print("Missing handler names:\n" + "\n".join(missing))
    sys.exit(1)
print("All case-label names covered. Semantic parity requires guest fixtures.")
