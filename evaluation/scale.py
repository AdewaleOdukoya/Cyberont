#!/usr/bin/env python3
"""Generate scaled copies of the v2 scenario ABox (k copies of S1-S8) for scalability tests.
Usage: python3 scale.py <k> > cyberont-v2-x<k>.omn"""
import re, subprocess, sys, os
k = int(sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__))
omn = subprocess.run([sys.executable, os.path.join(here, "..", "ontology", "build_v2.py")], capture_output=True, text=True).stdout
head, tail = omn.split("Individual: :Attacker1", 1)
tail = "Individual: :Attacker1" + tail
names = set(re.findall(r"^Individual: :(\w+)", tail, flags=re.M))
pat = re.compile(r":(" + "|".join(sorted(names, key=len, reverse=True)) + r")\b")
parts = [head]
for i in range(k):
    parts.append(pat.sub(lambda m: f":{m.group(1)}_{i}", tail))
print("\n".join(parts))
