"""Check installed SDK documentation links against the source checkout."""

from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

readme, source = map(Path, sys.argv[1:])
try:
    ref = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                         capture_output=True, text=True)
    ref = ref.stdout.strip() if ref.returncode == 0 else "main"
except FileNotFoundError:
    ref = "main"
repository = "https://github.com/takehaya/Vinbero/blob/"
# Fenced examples must survive staging verbatim, and their syntax is not a link.
sections = re.split(r"(?m)^```[^\n]*$", readme.read_text())
source_sections = re.split(r"(?m)^```[^\n]*$", (source / "sdk/README.md").read_text())
assert sections[1::2] == source_sections[1::2], "SDK doc code examples changed during staging"
for target in re.findall(r"\]\(([^\s)]+)\)", "".join(sections[::2])):
    if target.startswith("#"):
        continue
    if target.startswith(repository):
        assert target.startswith(repository + ref + "/"), f"unversioned SDK doc link: {target}"
        relative = unquote(urlsplit(target).path).split("/blob/" + ref + "/", 1)[1]
        path = (source / relative).resolve()
        assert path.is_relative_to(source.resolve()) and path.exists(), f"missing SDK doc source: {target}"
        if ref != "main":
            tracked = subprocess.run(["git", "-C", str(source), "cat-file", "-e", ref + ":" + relative],
                                     capture_output=True)
            assert tracked.returncode == 0, f"missing SDK doc at pinned commit: {target}"
    elif not urlsplit(target).scheme:
        path = (readme.parent / unquote(urlsplit(target).path)).resolve()
        assert path.is_relative_to(readme.parent) and path.exists(), f"missing installed SDK doc: {target}"
print("[verify] SDK documentation links OK")
