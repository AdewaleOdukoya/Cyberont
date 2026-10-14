#!/usr/bin/env python3
"""Compare severity outputs against the reference labels.

Approaches compared (all read the same asserted scenario data from cyberont-v2.ttl):
  * CyberOnt v2   - HermiT-inferred class (results/severity_v2.tsv, produced by `Evaluate severity`)
  * CyberOnt v1 rule - v1 axiom: Incident and affectsAsset some CriticalAsset and involvesThreat some RansomwareAttack
                     (results/severity_v1rule_on_v2data.tsv)
  * CVSS-only     - max CVSS v3.1 base score of exploited vulnerabilities: >=7.0 High, 4.0-6.9 Medium, <4.0 Low
  * Criticality-only - FIPS 199 level of the most critical affected asset: High->High, Moderate->Medium, Low->Low
Reference labels: reference_labels.tsv (matrix of Table III applied manually to each scenario record).

Usage: python3 baselines.py
"""
import csv, os, json
from rdflib import Graph, Namespace, RDF

here = os.path.dirname(os.path.abspath(__file__))
B = Namespace("http://www.semanticweb.org/mac/ontologies/2025/10/cybersecurity/")
g = Graph().parse(os.path.join(here, "..", "ontology", "cyberont-v2.ttl"))

def short(u): return str(u).rsplit("/", 1)[-1]

incidents = sorted({short(s) for s in g.subjects(RDF.type, B.Incident)})
ref = {r["incident"]: r["reference"] for r in csv.DictReader(open(os.path.join(here, "reference_labels.tsv")), delimiter="\t")}

def load_tsv(p):
    return dict(l.strip().split("\t") for l in open(os.path.join(here, "results", p)) if l.strip())

v2 = {k: v.replace("SeverityIncident", "") for k, v in load_tsv("severity_v2.tsv").items()}
v1 = {k: v.replace("SeverityIncident", "") for k, v in load_tsv("severity_v1rule_on_v2data.tsv").items()}

def cvss_only(i):
    scores = []
    for t in g.objects(B[i], B.involvesThreat):
        for v in g.objects(t, B.exploitsVulnerability):
            for s in g.objects(v, B.hasCVSSScore):
                scores.append(float(s))
    if not scores: return "Unclassified"
    m = max(scores)
    return "High" if m >= 7.0 else "Medium" if m >= 4.0 else "Low"

def crit_only(i):
    lv = [str(c) for a in g.objects(B[i], B.affectsAsset) for c in g.objects(a, B.hasCriticality)]
    if not lv: return "Unclassified"
    return "High" if "High" in lv else "Medium" if "Moderate" in lv else "Low"

rows, score = [], {"CyberOnt v2": 0, "v1 rule": 0, "CVSS-only": 0, "Criticality-only": 0}
for i in incidents:
    r = {"incident": i, "reference": ref[i], "CyberOnt v2": v2.get(i, "Unclassified"), "v1 rule": v1.get(i, "Unclassified"),
         "CVSS-only": cvss_only(i), "Criticality-only": crit_only(i)}
    for k in score:
        score[k] += r[k] == r["reference"]
    rows.append(r)

w = csv.DictWriter(open(os.path.join(here, "results", "baseline_comparison.tsv"), "w"), fieldnames=list(rows[0]), delimiter="\t")
w.writeheader(); w.writerows(rows)
for r in rows: print("\t".join(r.values()))
print(json.dumps({k: f"{v}/{len(incidents)}" for k, v in score.items()}))
