#!/usr/bin/env python3
"""
Standalone LLM vs ontology-grounded LLM on the CyberOnt v2 scenarios.

Conditions
  C1  LLM-only            : incident records (prose) + question. The model applies its own notion of severity.
  C2  LLM + policy        : C1 + the organisation's severity policy written in prose (same matrix as the ontology).
  C3  Ontology-grounded   : C2 + facts retrieved from the ontology after HermiT reasoning (inferred asset tier,
                            threat factor, severity class, and the DL-query answer set for list questions).
  C4  Text-to-DL-query    : the model is given the ontology schema and must write a Manchester-syntax DL query;
                            the harness executes it with HermiT and scores the returned set (list questions only).

Metrics (computed automatically against gold answers derived from the reasoner, see ../evaluation/results)
  correctness     : severity accuracy (8 incidents) and set F1 for the 16 competency questions
  hallucination   : share of answers that mention an entity, ATT&CK ID or CVSS value not present in the knowledge
                    base or not linked to the incident in question
  consistency     : agreement of k repeated samples (temperature > 0) and a paraphrase with the modal answer
  explainability  : explanation names both decisive factors (asset criticality and threat factor) -> 0, 1 or 2

Providers (stdlib only, no extra packages):
  --provider ollama     --model llama3.1:8b        (local, free; https://ollama.com, default http://localhost:11434)
  --provider openai     --model gpt-4o-mini        (needs OPENAI_API_KEY; --base-url for any OpenAI-compatible server)
  --provider anthropic  --model <model id>         (needs ANTHROPIC_API_KEY)
  --provider mock                                   (pipeline self-test only; NOT a result)

Example
  python3 run_llm_eval.py --provider ollama --model llama3.1:8b --samples 5 --out results_llama31.json
"""
import argparse, collections, csv, json, os, random, re, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.join(HERE, "..", "evaluation")
ONT = os.path.join(HERE, "..", "ontology", "cyberont-v2.ttl")
JAR = os.environ.get("ROBOT_JAR", os.path.join(HERE, "..", "tools", "robot.jar"))
BASE = "http://www.semanticweb.org/mac/ontologies/2025/10/cybersecurity/"
LEVELS = ["High", "Medium", "Low", "Undetermined"]

# ------------------------------------------------------------------ knowledge base (asserted + inferred)
def load_kb():
    from rdflib import Graph, Namespace, RDF, RDFS, OWL
    B = Namespace(BASE)
    g = Graph().parse(ONT)
    short = lambda u: str(u).rsplit("/", 1)[-1]
    kb = collections.defaultdict(lambda: collections.defaultdict(list))
    for s, p, o in g:
        if isinstance(s, type(B.x)) and str(s).startswith(BASE) and (s, RDF.type, OWL.NamedIndividual) in g:
            if p == RDF.type and str(o).startswith(BASE):
                kb[short(s)]["type"].append(short(o))
            elif str(p).startswith(BASE):
                kb[short(s)][short(p)].append(short(o) if str(o).startswith(BASE) else str(o))
            elif p == RDFS.label:
                kb[short(s)]["label"].append(str(o))
    inferred = {}
    for line in open(os.path.join(EVAL, "results", "inferred_types_v2.tsv")):
        n, t = line.rstrip("\n").split("\t")
        inferred[n] = t.split(",") if t else []
    return kb, inferred

def narrative(kb, inc):
    d = kb[inc]
    parts = [f"{inc} (status {d['hasStatus'][0]}, recorded {d['hasTimestamp'][0]})"]
    for a in d["affectsAsset"]:
        ad = kb[a]
        crit = ad["hasCriticality"][0] if ad["hasCriticality"] else "not recorded"
        parts.append(f"affects {a}, a {ad['type'][0]} whose business criticality is {crit}")
    for t in d["involvesThreat"]:
        td = kb[t]
        techs = ", ".join(f"{x} ({kb[x]['label'][0]})" for x in td["usesTechnique"]) or "no recorded ATT&CK technique"
        vulns = []
        for v in td["exploitsVulnerability"]:
            vd = kb[v]
            sc = vd["hasCVSSScore"][0] if vd["hasCVSSScore"] else "unscored"
            vulns.append(f"{v} ({vd['type'][0]}, CVSS v3.1 base score {sc})")
        parts.append(f"involves {t}, a {td['type'][0]} using {techs}" + (f" and exploiting {', '.join(vulns)}" if vulns else " and exploiting no recorded vulnerability"))
    if d["causedBy"]:
        parts.append(f"was caused by {d['causedBy'][0]} ({kb[d['causedBy'][0]]['type'][0]})")
    return "; ".join(parts) + "."

def controls_text(kb):
    out = []
    for n, d in sorted(kb.items()):
        if any(k in d for k in ("protectsAsset", "mitigatesThreat", "mitigatesVulnerability")) and "reportsIncident" not in d:
            bits = [f"protects {', '.join(d['protectsAsset'])}"] if d["protectsAsset"] else []
            if d["mitigatesThreat"]: bits.append(f"mitigates threat {', '.join(d['mitigatesThreat'])}")
            if d["mitigatesVulnerability"]: bits.append(f"mitigates vulnerability {', '.join(d['mitigatesVulnerability'])}")
            out.append(f"{n} ({d['type'][0]}) " + "; ".join(bits) + ".")
        if "reportsIncident" in d:
            out.append(f"{n} (Alert) was generated by {d['generatedBy'][0]} and reports {d['reportsIncident'][0]}.")
    return "\n".join(out)

POLICY = (
    "Severity policy. Asset criticality uses FIPS 199 levels (High, Moderate, Low). A threat is SEVERE if it uses a "
    "MITRE ATT&CK technique listed under the Impact tactic (TA0040) or exploits a vulnerability with CVSS v3.1 base "
    "score >= 7.0; otherwise it is NON-SEVERE, provided the record is complete. Severity is the cell of this matrix "
    "taken over the most critical affected asset and the most severe threat: High asset + severe -> High; High asset + "
    "non-severe -> Medium; Moderate asset + severe -> Medium; Moderate asset + non-severe -> Low; Low asset + any -> "
    "Low. If asset criticality or threat information is missing, answer Undetermined."
)

def grounding(kb, inferred, inc):
    lines = []
    d = kb[inc]
    for a in d["affectsAsset"]:
        tier = [t for t in inferred.get(a, []) if t in ("CriticalAsset", "ModerateCriticalityAsset", "LowCriticalityAsset")]
        lines.append(f"{a} is inferred to be: {tier[0] if tier else 'no criticality tier (insufficient data)'}")
    for t in d["involvesThreat"]:
        f = [x for x in inferred.get(t, []) if x in ("SevereThreat", "NonSevereThreat", "HighImpactThreat")]
        lines.append(f"{t} is inferred to be: {', '.join(f) if f else 'neither SevereThreat nor NonSevereThreat (insufficient data)'}")
        for v in kb[t]["exploitsVulnerability"]:
            vf = [x for x in inferred.get(v, []) if x in ("SevereVulnerability", "CriticalVulnerability", "NonSevereVulnerability")]
            lines.append(f"{v} is inferred to be: {', '.join(vf) if vf else 'unscored'}")
        for x in kb[t]["usesTechnique"]:
            if "ImpactTechnique" in inferred.get(x, []):
                lines.append(f"{x} is an ImpactTechnique (ATT&CK TA0040)")
    sev = [x for x in inferred.get(inc, []) if x.endswith("SeverityIncident")]
    lines.append(f"HermiT classifies {inc} as: {sev[0] if sev else 'no severity class (Undetermined)'}")
    return "\n".join(lines)

# ------------------------------------------------------------------ questions and gold answers
def build_items(kb, inferred):
    gold_sev = {}
    for line in open(os.path.join(EVAL, "results", "severity_v2.tsv")):
        n, s = line.strip().split("\t")
        gold_sev[n] = s.replace("SeverityIncident", "") if s != "Unclassified" else "Undetermined"
    cqs = list(csv.DictReader(open(os.path.join(EVAL, "competency_questions.tsv")), delimiter="\t"))
    items = []
    for inc, g in sorted(gold_sev.items()):
        items.append({"id": f"SEV-{inc}", "kind": "severity", "incident": inc, "gold": g,
                      "q": f"What is the severity of {inc} (High, Medium, Low or Undetermined)? Justify briefly.",
                      "q_para": f"How severe should {inc} be rated: High, Medium, Low, or Undetermined? Give the reasons."})
    for c in cqs:
        items.append({"id": c["id"], "kind": "list", "gold": sorted(c["expected"].split(",")), "dl": c["dl_query"],
                      "q": c["question"], "q_para": "Please list: " + c["question"][0].lower() + c["question"][1:]})
    return items

# ------------------------------------------------------------------ prompts
SYSTEM = ("You are a security operations assistant. Answer only from the information provided. "
          "Finish with a line 'ANSWER: <answer>' where <answer> is one of High/Medium/Low/Undetermined for severity "
          "questions, or a comma-separated list of individual names for list questions (or NONE).")

SCHEMA = ("Classes: Incident, HighSeverityIncident, MediumSeverityIncident, LowSeverityIncident, CyberAsset, CriticalAsset, "
          "ModerateCriticalityAsset, LowCriticalityAsset, Server, Workstation, Application, UserAccount, Threat, RansomwareAttack, "
          "MalwareAttack, TrojanAttack, PhishingAttack, BruteForceAttack, DDoSAttack, HighImpactThreat, SevereThreat, NonSevereThreat, "
          "Vulnerability, UnpatchedSoftware, WeakPassword, OpenPort, Misconfiguration, SevereVulnerability, NonSevereVulnerability, "
          "SecurityControl, BackupSystem, Antivirus, FirewallRule, MultiFactorAuthentication, SecurityAwarenessTraining, "
          "DDoSMitigationService, Alert, Actor, ExternalAttacker, Insider, AttackTechnique, ImpactTechnique, AttackTactic.\n"
          "Object properties: affectsAsset, involvesThreat, exploitsVulnerability, targetsAsset, causedBy, protectsAsset, "
          "mitigatesThreat, mitigatesVulnerability, generatedBy, reportsIncident, hasVulnerability, usesTechnique, partOfTactic.\n"
          "Data properties: hasCVSSScore, hasCriticality, hasStatus. Tactic individuals: TA0001 ... TA0040 (TA0006 = Credential Access).\n"
          "Write ONE OWL Manchester-syntax class expression, e.g. Incident and (affectsAsset some CriticalAsset). "
          "Use 'inverse (p)' for inverse properties and 'p value X' for individuals. Reply with 'QUERY: <expression>' only.")

def prompt(item, cond, kb, inferred, records, ctrls, paraphrase=False):
    q = item["q_para"] if paraphrase else item["q"]
    ctx = f"Incident records:\n{records}\n\nSecurity controls and alerts:\n{ctrls}\n"
    if cond == "C1":
        return ctx + f"\nQuestion: {q}"
    if cond == "C2":
        return ctx + f"\n{POLICY}\n\nQuestion: {q}"
    if cond == "C3":
        if item["kind"] == "severity":
            facts = grounding(kb, inferred, item["incident"])
        else:
            facts = f"Ontology query `{item['dl']}` returned (HermiT): {', '.join(item['gold']) if item['gold'] else 'no individuals'}"
        return ctx + f"\n{POLICY}\n\nVerified facts from the ontology reasoner (authoritative):\n{facts}\n\nQuestion: {q}"
    if cond == "C4":
        return f"{SCHEMA}\n\nQuestion: {q}"
    raise ValueError(cond)

# ------------------------------------------------------------------ providers
def call(provider, model, system, user, temperature, base_url=None):
    if provider == "mock":
        m = re.findall(r"HermiT classifies \w+ as: (\w+)", user)
        if m:
            lvl = m[0].replace("SeverityIncident", "") if "Severity" in m[0] else "Undetermined"
            return f"Mock explanation citing criticality and threat. ANSWER: {lvl}"
        m = re.findall(r"returned \(HermiT\): (.*)", user)
        if m:
            return f"ANSWER: {m[0]}"
        if "QUERY:" in system + user:
            return "QUERY: Incident"
        return "ANSWER: " + random.choice(LEVELS)
    if provider == "ollama":
        url = (base_url or "http://localhost:11434") + "/api/chat"
        body = {"model": model, "stream": False, "keep_alive": "30m", "options": {"temperature": temperature, "num_ctx": 8192},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        r = json.load(urllib.request.urlopen(urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"}), timeout=600))
        return r["message"]["content"]
    if provider == "openai":
        url = (base_url or "https://api.openai.com/v1") + "/chat/completions"
        body = {"model": model, "temperature": temperature,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]})
        return json.load(urllib.request.urlopen(req, timeout=600))["choices"][0]["message"]["content"]
    if provider == "anthropic":
        url = (base_url or "https://api.anthropic.com") + "/v1/messages"
        body = {"model": model, "max_tokens": 800, "temperature": temperature, "system": system,
                "messages": [{"role": "user", "content": user}]}
        req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", "x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"})
        return json.load(urllib.request.urlopen(req, timeout=600))["content"][0]["text"]
    raise ValueError(provider)

# ------------------------------------------------------------------ scoring
LEVEL_RE = r"(High|Medium|Low|Undetermined)"

def parse_answer(text, kind):
    """Severity: the ANSWER line if present; otherwise an explicit 'severity ... is <Level>' statement;
    otherwise the last severity word in the text. Lists: the ANSWER line, else the last line."""
    m = re.findall(r"ANSWER:\s*(.+)", text)
    if kind == "severity":
        if m:
            f = re.findall(LEVEL_RE, m[-1], flags=re.I)
            if f:
                return f[0].capitalize()
        f = re.findall(r"(?:severity|severe|rated|rating)[^.\n]{0,60}?\b(?:is|as|be|of)\s+(?:rated\s+)?(?:as\s+)?\**" + LEVEL_RE, text, flags=re.I)
        if f:
            return f[-1].capitalize()
        f = re.findall(r"\b" + LEVEL_RE + r"\b", text)
        return f[-1] if f else "Unparsed"
    a = m[-1].strip() if m else (text.strip().splitlines()[-1] if text.strip() else "")
    if a.strip().upper().startswith("NONE"):
        return []
    return sorted({x.strip(" .*`") for x in re.split(r"[,;\s]+", a) if re.match(r"^[A-Za-z]+\d+[A-Za-z0-9_]*$", x.strip(" .*`"))})

def f1(pred, gold):
    p, g = set(pred), set(gold)
    if not p and not g: return 1.0
    tp = len(p & g)
    return 0.0 if tp == 0 else 2 * tp / (len(p) + len(g))

def hallucinated(text, item, kb):
    """True if the answer mentions an unknown entity, an ATT&CK ID or CVSS value not linked to the incident."""
    names = set(re.findall(r"\b[A-Z][A-Za-z]+\d+\b", text))
    if any(n not in kb for n in names):
        return True
    if item["kind"] == "severity":
        inc = item["incident"]
        threats = kb[inc]["involvesThreat"]
        techs = {x for t in threats for x in kb[t]["usesTechnique"]}
        scores = {float(kb[v]["hasCVSSScore"][0]) for t in threats for v in kb[t]["exploitsVulnerability"] if kb[v]["hasCVSSScore"]}
        for tid in re.findall(r"\bT\d{4}\b", text):
            if tid not in techs:
                return True
        allowed = scores | {7.0, 9.0}
        for sc in re.findall(r"(?<![v\d.])(\d{1,2}\.\d)(?![\d.])", text):
            if float(sc) not in allowed:
                return True
    return False

def explanation_score(text, item, kb):
    if item["kind"] != "severity": return None
    t = text.lower()
    inc = item["incident"]
    s = 0
    crit_terms = ["critical", "criticality", "moderate", "fips"]
    if any(a.lower() in t for a in kb[inc]["affectsAsset"]) and any(w in t for w in crit_terms): s += 1
    threat_terms = ["impact", "ta0040", "cvss", "severe", "t1486", "t1498"]
    if any(th.lower() in t for th in kb[inc]["involvesThreat"]) and any(w in t for w in threat_terms): s += 1
    return s

def run_query(expr):
    out = subprocess.run(["java", "-cp", f"{JAR}:{EVAL}", "Evaluate", "query", ONT, expr], capture_output=True, text=True).stdout
    lines = [l for l in out.splitlines() if l and not l[:4].isdigit()]
    if lines and lines[0].startswith("PARSE_ERROR"):
        return None
    return sorted(lines)


def summarise(rows):
    sev = [r for r in rows if r["kind"] == "severity"]
    lst = [r for r in rows if r["kind"] == "list"]
    mean = lambda xs: round(sum(xs) / len(xs), 3) if xs else None
    return {"severity_accuracy": mean([1.0 if r["correct"] else 0.0 for r in sev]),
            "cq_mean_f1": mean([r["correct"] for r in lst]),
            "hallucination_rate": mean([1.0 if r["hallucination"] else 0.0 for r in rows if r["hallucination"] is not None]),
            "consistency": mean([r["consistency"] for r in rows]),
            "explanation_score_0to2": mean([r["explanation"] for r in rows if r["explanation"] is not None]),
            "n_items": len(rows),
            "empty_or_error_replies": sum(r.get("empty", 0) for r in rows)}

def rescore(paths, items, kb, out):
    # a later file replaces every condition it contains (e.g. a re-run of C2,C3)
    per_cond = {}
    for p in paths:
        d = json.load(open(p))
        conds_here = {x["cond"] for x in d["log"]}
        for c in conds_here:
            per_cond[c] = [x for x in d["log"] if x["cond"] == c]
    logs = [x for c in sorted(per_cond) for x in per_cond[c]]
    by = collections.defaultdict(list)
    for x in logs:
        by[(x["cond"], x["id"])].append(x)
    conds = sorted({c for c, _ in by})
    summary, allrows = {}, {}
    for cond in conds:
        rows = []
        for it in items:
            outs = by.get((cond, it["id"]))
            if not outs:
                continue
            # usable replies only; if a condition was re-run, the later (non-empty) replies win
            good = [o for o in outs if o["text"].strip() and not o["text"].startswith("ERROR")]
            empty = len(outs) - len(good)
            if not good:
                continue
            if cond != "C4":
                for o in good:
                    o["answer"] = parse_answer(o["text"], it["kind"])
            prim = [o for o in good if o["temp"] == 0.0 and not o["paraphrase"]]
            primary = prim[-1] if prim else good[0]
            correct = (primary["answer"] == it["gold"]) if it["kind"] == "severity" else f1(primary["answer"], it["gold"])
            keyed = [json.dumps(o["answer"]) for o in good]
            modal = collections.Counter(keyed).most_common(1)[0][1] / len(keyed)
            rows.append({"id": it["id"], "kind": it["kind"], "gold": it["gold"], "answer": primary["answer"],
                         "correct": correct, "consistency": modal, "n_replies": len(good), "empty": empty,
                         "hallucination": None if cond == "C4" else hallucinated(primary["text"], it, kb),
                         "explanation": None if cond == "C4" else explanation_score(primary["text"], it, kb)})
        summary[cond] = summarise(rows)
        allrows[cond] = rows
    json.dump({"rescored_from": paths, "summary": summary, "rows": allrows}, open(out, "w"), indent=1)
    print(json.dumps(summary, indent=1))

# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="mock", choices=["ollama", "openai", "anthropic", "mock"])
    ap.add_argument("--model", default="")
    ap.add_argument("--base-url")
    ap.add_argument("--samples", type=int, default=5, help="samples per question at --temperature (consistency)")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--conditions", default="C1,C2,C3,C4")
    ap.add_argument("--out", default="llm_results.json")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rescore", nargs="+", help="recompute metrics from saved result files (merged), no model calls")
    a = ap.parse_args()
    random.seed(a.seed)

    kb, inferred = load_kb()
    items = build_items(kb, inferred)
    incs = sorted(n for n in kb if "Incident" in kb[n]["type"])
    records = "\n".join("- " + narrative(kb, i) for i in incs)
    ctrls = controls_text(kb)

    if a.rescore:
        rescore(a.rescore, items, kb, a.out)
        return

    log, summary = [], {}
    for cond in a.conditions.split(","):
        rows = []
        for it in items:
            if cond == "C4" and it["kind"] != "list":
                continue
            outs = []
            # deterministic answer (temperature 0) + k stochastic samples + 1 paraphrase
            plan = [(0.0, False)] + [(a.temperature, False)] * a.samples + [(0.0, True)]
            for temp, para in plan:
                p = prompt(it, cond, kb, inferred, records, ctrls, para)
                sysmsg = "You translate questions into OWL DL queries." if cond == "C4" else SYSTEM
                t0 = time.time()
                txt = ""
                for attempt in range(4):          # retry empty or failed replies
                    try:
                        txt = call(a.provider, a.model, sysmsg, p, temp, a.base_url)
                    except Exception as e:
                        txt = f"ERROR {e}"
                    if txt.strip() and not txt.startswith("ERROR"):
                        break
                    print(f"  retry {attempt + 1} for {cond} {it['id']}: {txt[:80]!r}", file=sys.stderr)
                    time.sleep(5 * (attempt + 1))
                dt = time.time() - t0
                if cond == "C4":
                    m = re.findall(r"QUERY:\s*(.+)", txt)
                    expr = m[-1].strip().strip("`") if m else ""
                    ans = run_query(expr) if expr else None
                    ans = ans if ans is not None else ["<invalid query>"]
                else:
                    ans = parse_answer(txt, it["kind"])
                outs.append({"temp": temp, "paraphrase": para, "text": txt, "answer": ans, "latency_s": round(dt, 2)})
                log.append({"cond": cond, "id": it["id"], **outs[-1]})
            primary = outs[0]
            correct = (primary["answer"] == it["gold"]) if it["kind"] == "severity" else f1(primary["answer"], it["gold"])
            keyed = [json.dumps(o["answer"]) for o in outs]
            modal = collections.Counter(keyed).most_common(1)[0][1] / len(keyed)
            row = {"id": it["id"], "kind": it["kind"], "gold": it["gold"], "answer": primary["answer"], "correct": correct,
                   "consistency": modal,
                   "hallucination": None if cond == "C4" else hallucinated(primary["text"], it, kb),
                   "explanation": None if cond == "C4" else explanation_score(primary["text"], it, kb)}
            rows.append(row)
            print(cond, it["id"], row["answer"], "gold", it["gold"], file=sys.stderr)
        sev = [r for r in rows if r["kind"] == "severity"]
        lst = [r for r in rows if r["kind"] == "list"]
        mean = lambda xs: round(sum(xs) / len(xs), 3) if xs else None
        summary[cond] = {
            "severity_accuracy": mean([1.0 if r["correct"] else 0.0 for r in sev]),
            "cq_mean_f1": mean([r["correct"] for r in lst]),
            "hallucination_rate": mean([1.0 if r["hallucination"] else 0.0 for r in rows if r["hallucination"] is not None]),
            "consistency": mean([r["consistency"] for r in rows]),
            "explanation_score_0to2": mean([r["explanation"] for r in rows if r["explanation"] is not None]),
            "n_items": len(rows),
        }
        summary[cond + "_rows"] = rows
    json.dump({"provider": a.provider, "model": a.model, "samples": a.samples, "temperature": a.temperature,
               "summary": {k: v for k, v in summary.items() if not k.endswith("_rows")}, "rows": {k: v for k, v in summary.items() if k.endswith("_rows")},
               "log": log}, open(a.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in summary.items() if not k.endswith("_rows")}, indent=1))

if __name__ == "__main__":
    main()
