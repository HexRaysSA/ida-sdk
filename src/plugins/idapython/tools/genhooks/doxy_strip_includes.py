"""
Doxygen INPUT_FILTER: blank out #include directives.

doxygen 1.16+ has a bug where an INPUT file that #includes another INPUT
header guarded by #pragma once loses all of its own content after that
include (the included file is "already processed", and doxygen then
discards the rest of the including file). Blanking the #include lines
before doxygen sees them sidesteps the bug for every header at once,
without per-header markup. Lines are replaced with empty lines so line
numbers are preserved.
"""
import sys
import re

pat = re.compile(r"^\s*#\s*include\b")

def main():
    sys.stdout.reconfigure(encoding="utf-8", newline="")
    with open(sys.argv[1], encoding="utf-8", errors="replace") as fin:
        for line in fin:
            sys.stdout.write("\n" if pat.match(line) else line)

if __name__ == "__main__":
    main()
