# CyberOnt: a standards-aligned cybersecurity incident ontology

This repository holds the artefacts behind the paper *A Standards-Aligned Cybersecurity Incident Ontology for
Explainable Severity Reasoning in Modern Enterprises* (Odukoya and Akram). It includes the ontology files,
competency questions, scenarios, reference labels, evaluation code, raw results and the LLM evaluation harness.

## Contents

| Path | What it is |
|---|---|
| `ontology/cyberont-v1.ttl` | Original Protégé ontology (v1), extracted unchanged from the first manuscript |
| `ontology/build_v2.py` | Generator for v2 (Manchester syntax). Run `python3 build_v2.py > cyberont-v2.omn` |
| `ontology/cyberont-v2.{omn,ttl,owl}` | CyberOnt v2: TBox, ATT&CK individuals and the eight scenarios S1–S8 |
| `evaluation/competency_questions.tsv` | The 16 competency questions with their DL queries and expected answers |
| `evaluation/reference_labels.tsv` | Reference severity for each scenario, with the rationale |
| `evaluation/Evaluate.java` | HermiT harness: metrics, timing, CQs, severity, fault injection, disjointness, single queries |
| `evaluation/baselines.py` | Comparison of v2, the v1 rule, CVSS-only and criticality-only triage |
| `evaluation/scale.py` | Generates *k* replicated copies of the scenario set for the scalability test |
| `evaluation/results/` | Raw outputs reported in the paper |
| `llm_eval/run_llm_eval.py` | Standalone vs ontology-grounded LLM experiment (conditions C1–C4) |
| `figures/` | Graphviz sources and PNGs for Figs. 1–4 |

## Requirements

* Java 11+ (tested with OpenJDK 21)
* ROBOT 1.9.6 (`robot.jar`, which bundles OWL API 4.5.29 and HermiT 1.4.5.456):
  https://github.com/ontodev/robot/releases/tag/v1.9.6. Put it at `tools/robot.jar`.
* Python 3.10+ with `rdflib` (`pip install rdflib`)

## Reproduce the ontology results

```bash
cd ontology
python3 build_v2.py > cyberont-v2.omn
java -jar ../tools/robot.jar convert -i cyberont-v2.omn -o cyberont-v2.ttl

cd ../evaluation
javac -cp ../tools/robot.jar Evaluate.java
J="java -cp ../tools/robot.jar:. Evaluate"      # on Windows use ; instead of :
$J metrics  ../ontology/cyberont-v2.ttl          # Table V metrics
$J reason   ../ontology/cyberont-v2.ttl 30       # consistency + classification + realisation timing
$J severity ../ontology/cyberont-v2.ttl > results/severity_v2.tsv
$J cq       ../ontology/cyberont-v2.ttl competency_questions.tsv 30 > results/cq_v2.json
$J faults   ../ontology/cyberont-v2.ttl          # Table VII
$J disjoint ../ontology/cyberont-v2.ttl          # severity classes disjoint by entailment
$J types    ../ontology/cyberont-v2.ttl > results/inferred_types_v2.tsv
python3 baselines.py                              # Table VI agreement row
```

Justifications (explanations) are produced with ROBOT, for example:

```bash
java -jar ../tools/robot.jar explain -i ../ontology/cyberont-v2.ttl --reasoner HermiT \
  -M entailment --axiom "Incident3 Type: MediumSeverityIncident" --explanation results/explain_Incident3.md
```

Open `ontology/cyberont-v2.owl` in Protégé (5.6.4 or later), start HermiT and use the DL Query tab to run any query
from `competency_questions.tsv`.

## Run the LLM experiment (Section VI)

Using a free local model:

1. Install Ollama (https://ollama.com), then run `ollama pull llama3.1:8b`.
2. Run:

```bash
cd llm_eval
python3 run_llm_eval.py --provider ollama --model llama3.1:8b --samples 5 --out results_llama31_8b.json
```

Using a hosted model (optional):

```bash
export OPENAI_API_KEY=...      # or ANTHROPIC_API_KEY=...
python3 run_llm_eval.py --provider openai --model gpt-4o-mini --out results_gpt4omini.json
```

The script prints a summary per condition (severity accuracy, CQ F1, hallucination rate, consistency, explanation
score) and writes every prompt response to the output JSON. `--provider mock` only checks that the pipeline runs and
does not produce results.

## LLM results reported in the paper

`llm_eval/results_llama32_3b_C1.json` and `llm_eval/results_llama32_3b_C2C3.json` hold the raw responses (Llama 3.2 3B
via Ollama). Table VIII is produced by re-scoring them together:

```bash
python3 run_llm_eval.py --rescore results_llama32_3b_C1.json results_llama32_3b_C2C3.json --out results_llama32_3b_rescored.json
```

`results_llama31_8b_run1.json` is an incomplete pilot run with Llama 3.1 8B (it stalled while the laptop slept) and is
not reported.

## Licence

* Ontology files, competency questions, scenarios, reference labels and results (`ontology/`, `evaluation/*.tsv`, `evaluation/results/`, `llm_eval/*.json`, `figures/`): Creative Commons Attribution 4.0 International (CC BY 4.0). See `LICENSE-DATA`.
* Source code (`*.py`, `*.java`): MIT licence. See `LICENSE`.

If you use CyberOnt, please cite the paper.
