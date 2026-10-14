import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.*;
import org.semanticweb.owlapi.reasoner.*;
import org.semanticweb.owlapi.util.*;
import org.semanticweb.owlapi.util.mansyntax.ManchesterOWLSyntaxParser;
import org.semanticweb.owlapi.expression.ShortFormEntityChecker;
import org.semanticweb.owlapi.search.EntitySearcher;

/**
 * Reproducible HermiT evaluation of CyberOnt.
 * Compile: javac -cp robot.jar Evaluate.java
 * Run:     java -cp robot.jar:. Evaluate <mode> <args...>
 *   metrics  <ontology>
 *   reason   <ontology> <runs>                       (consistency + classification + realisation timing)
 *   cq       <ontology> <cq.tsv> <runs>              (DL-query competency questions, Protégé DL Query equivalent)
 *   severity <ontology>                              (inferred severity class of each Incident)
 *   faults   <ontology>                              (fault-injection tests)
 *   disjoint <ontology>                              (are severity classes disjoint without the asserted axiom?)
 */
public class Evaluate {
    static OWLOntologyManager man;
    static OWLDataFactory df;
    static OWLOntology ont;
    static String BASE = "http://www.semanticweb.org/mac/ontologies/2025/10/cybersecurity/";
    static OWLReasonerFactory rf = new org.semanticweb.HermiT.ReasonerFactory();

    static void load(String path) throws Exception {
        man = OWLManager.createOWLOntologyManager();
        df = man.getOWLDataFactory();
        ont = man.loadOntologyFromOntologyDocument(new File(path));
    }

    static String sf(OWLEntity e) {
        String s = e.getIRI().toString();
        int i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('#'));
        return s.substring(i + 1);
    }

    static OWLReasoner fresh() { return rf.createReasoner(ont); }

    static ManchesterOWLSyntaxParser parser() {
        ManchesterOWLSyntaxParser p = OWLManager.createManchesterParser();
        BidirectionalShortFormProvider sfp = new BidirectionalShortFormProviderAdapter(man, Collections.singleton(ont), new SimpleShortFormProvider());
        p.setOWLEntityChecker(new ShortFormEntityChecker(sfp));
        p.setDefaultOntology(ont);
        return p;
    }

    static OWLClassExpression parse(String s) {
        ManchesterOWLSyntaxParser p = parser();
        p.setStringToParse(s);
        return p.parseClassExpression();
    }

    static double[] stats(List<Double> xs) {
        double m = xs.stream().mapToDouble(d -> d).average().orElse(0);
        double sd = Math.sqrt(xs.stream().mapToDouble(d -> (d - m) * (d - m)).sum() / Math.max(1, xs.size() - 1));
        List<Double> s = new ArrayList<>(xs); Collections.sort(s);
        return new double[]{m, sd, s.get(s.size() / 2), s.get(0), s.get(s.size() - 1)};
    }

    public static void main(String[] a) throws Exception {
        String mode = a[0];
        load(a[1]);
        switch (mode) {
            case "metrics": metrics(); break;
            case "reason": reason(Integer.parseInt(a[2])); break;
            case "cq": cq(a[2], Integer.parseInt(a[3])); break;
            case "severity": severity(); break;
            case "faults": faults(); break;
            case "disjoint": disjoint(); break;
            case "query": query(a[2]); break;
            case "types": {
                OWLReasoner rs = fresh();
                List<OWLNamedIndividual> all = new ArrayList<>(ont.getIndividualsInSignature());
                all.sort(Comparator.comparing(Evaluate::sf));
                for (OWLNamedIndividual i : all)
                    System.out.println(sf(i) + "\t" + rs.getTypes(i, false).getFlattened().stream().filter(x -> !x.isOWLThing()).map(Evaluate::sf).sorted().collect(Collectors.joining(",")));
                rs.dispose(); break;
            }
        }
    }

    static void metrics() {
        Set<OWLOntology> s = Collections.singleton(ont);
        System.out.println("{");
        System.out.println("  \"classes\": " + ont.getClassesInSignature().size() + ",");
        System.out.println("  \"object_properties\": " + ont.getObjectPropertiesInSignature().size() + ",");
        System.out.println("  \"data_properties\": " + ont.getDataPropertiesInSignature().size() + ",");
        System.out.println("  \"individuals\": " + ont.getIndividualsInSignature().size() + ",");
        System.out.println("  \"axioms\": " + ont.getAxiomCount() + ",");
        System.out.println("  \"logical_axioms\": " + ont.getLogicalAxiomCount() + ",");
        System.out.println("  \"tbox_axioms\": " + ont.getTBoxAxioms(org.semanticweb.owlapi.model.parameters.Imports.EXCLUDED).size() + ",");
        System.out.println("  \"rbox_axioms\": " + ont.getRBoxAxioms(org.semanticweb.owlapi.model.parameters.Imports.EXCLUDED).size() + ",");
        System.out.println("  \"abox_axioms\": " + ont.getABoxAxioms(org.semanticweb.owlapi.model.parameters.Imports.EXCLUDED).size() + ",");
        System.out.println("  \"equivalent_class_axioms\": " + ont.getAxiomCount(AxiomType.EQUIVALENT_CLASSES) + ",");
        System.out.println("  \"subclass_axioms\": " + ont.getAxiomCount(AxiomType.SUBCLASS_OF) + ",");
        System.out.println("  \"disjoint_class_axioms\": " + ont.getAxiomCount(AxiomType.DISJOINT_CLASSES) + ",");
        System.out.println("  \"class_assertions\": " + ont.getAxiomCount(AxiomType.CLASS_ASSERTION) + ",");
        System.out.println("  \"object_property_assertions\": " + ont.getAxiomCount(AxiomType.OBJECT_PROPERTY_ASSERTION) + ",");
        System.out.println("  \"data_property_assertions\": " + ont.getAxiomCount(AxiomType.DATA_PROPERTY_ASSERTION) + ",");
        System.out.println("  \"annotation_assertions\": " + ont.getAxiomCount(AxiomType.ANNOTATION_ASSERTION) + ",");
        System.out.println("  \"dl_expressivity\": \"" + new DLExpressivityChecker(s).getDescriptionLogicName() + "\"");
        System.out.println("}");
    }

    static void reason(int runs) {
        List<Double> load = new ArrayList<>(), cls = new ArrayList<>(), real = new ArrayList<>(), tot = new ArrayList<>();
        boolean consistent = true; int unsat = -1; int inferredTypes = 0;
        int warm = runs >= 5 ? 3 : 0;
        for (int r = 0; r < runs + warm; r++) {   // warm-up runs discarded
            long t0 = System.nanoTime();
            OWLReasoner rs = fresh();
            consistent = rs.isConsistent();
            long t1 = System.nanoTime();
            rs.precomputeInferences(InferenceType.CLASS_HIERARCHY);
            long t2 = System.nanoTime();
            rs.precomputeInferences(InferenceType.CLASS_ASSERTIONS);
            long t3 = System.nanoTime();
            unsat = rs.getUnsatisfiableClasses().getEntitiesMinusBottom().size();
            if (r == 0) {
                for (OWLNamedIndividual i : ont.getIndividualsInSignature())
                    inferredTypes += rs.getTypes(i, false).getFlattened().size();
            }
            rs.dispose();
            if (r >= warm) {
                load.add((t1 - t0) / 1e6); cls.add((t2 - t1) / 1e6); real.add((t3 - t2) / 1e6); tot.add((t3 - t0) / 1e6);
            }
        }
        double[] a = stats(load), b = stats(cls), c = stats(real), d = stats(tot);
        System.out.printf(Locale.ROOT, "{\"runs\": %d, \"consistent\": %s, \"unsatisfiable_classes\": %d, \"inferred_type_links\": %d,%n", runs, consistent, unsat, inferredTypes);
        System.out.printf(Locale.ROOT, " \"consistency_ms\": [%.2f, %.2f, %.2f], \"classification_ms\": [%.2f, %.2f, %.2f], \"realisation_ms\": [%.2f, %.2f, %.2f], \"total_ms\": [%.2f, %.2f, %.2f]}%n",
                a[0], a[1], a[2], b[0], b[1], b[2], c[0], c[1], c[2], d[0], d[1], d[2]);
    }

    static void cq(String tsv, int runs) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(tsv));
        OWLReasoner rs = fresh();
        rs.precomputeInferences(InferenceType.CLASS_HIERARCHY, InferenceType.CLASS_ASSERTIONS);
        int passed = 0, total = 0;
        System.out.println("[");
        for (int li = 1; li < lines.size(); li++) {
            String[] f = lines.get(li).split("\t");
            if (f.length < 4) continue;
            total++;
            OWLClassExpression ce = parse(f[2]);
            Set<String> got = null; List<Double> times = new ArrayList<>();
            for (int r = 0; r < runs + 3; r++) {
                long t0 = System.nanoTime();
                Set<OWLNamedIndividual> inst = rs.getInstances(ce, false).getFlattened();
                long t1 = System.nanoTime();
                if (r >= 3) times.add((t1 - t0) / 1e6);
                got = inst.stream().map(Evaluate::sf).collect(Collectors.toCollection(TreeSet::new));
            }
            Set<String> exp = new TreeSet<>(Arrays.asList(f[3].split(",")));
            Set<String> tp = new TreeSet<>(got); tp.retainAll(exp);
            double prec = got.isEmpty() ? (exp.isEmpty() ? 1 : 0) : tp.size() / (double) got.size();
            double rec = exp.isEmpty() ? 1 : tp.size() / (double) exp.size();
            boolean ok = got.equals(exp);
            if (ok) passed++;
            double[] s = stats(times);
            System.out.printf(Locale.ROOT, "  {\"id\": \"%s\", \"answered\": %s, \"precision\": %.3f, \"recall\": %.3f, \"n_expected\": %d, \"n_returned\": %d, \"query_ms_mean\": %.3f, \"query_ms_sd\": %.3f, \"returned\": \"%s\"}%s%n",
                    f[0], ok, prec, rec, exp.size(), got.size(), s[0], s[1], String.join(",", got), li < lines.size() - 1 ? "," : "");
        }
        System.out.println("]");
        System.err.println("CQ passed: " + passed + "/" + total);
        rs.dispose();
    }

    /** Run one DL query (Manchester syntax) and print the instances, one per line; "PARSE_ERROR" on failure. */
    static void query(String expr) {
        OWLClassExpression ce;
        try { ce = parse(expr); } catch (Exception e) { System.out.println("PARSE_ERROR\t" + e.getMessage().split("\n")[0]); return; }
        OWLReasoner rs = fresh();
        for (OWLNamedIndividual i : rs.getInstances(ce, false).getFlattened()) System.out.println(sf(i));
        rs.dispose();
    }

    static void severity() {
        OWLReasoner rs = fresh();
        OWLClass inc = df.getOWLClass(IRI.create(BASE + "Incident"));
        String[] sev = {"HighSeverityIncident", "MediumSeverityIncident", "LowSeverityIncident"};
        List<OWLNamedIndividual> incs = new ArrayList<>(rs.getInstances(inc, false).getFlattened());
        incs.sort(Comparator.comparing(Evaluate::sf));
        for (OWLNamedIndividual i : incs) {
            Set<String> types = rs.getTypes(i, false).getFlattened().stream().map(Evaluate::sf).collect(Collectors.toSet());
            List<String> s = new ArrayList<>();
            for (String x : sev) if (types.contains(x)) s.add(x);
            System.out.println(sf(i) + "\t" + (s.isEmpty() ? "Unclassified" : String.join("+", s)));
        }
        rs.dispose();
    }

    static OWLNamedIndividual ind(String n) { return df.getOWLNamedIndividual(IRI.create(BASE + n)); }
    static OWLClass c(String n) { return df.getOWLClass(IRI.create(BASE + n)); }
    static OWLObjectProperty op(String n) { return df.getOWLObjectProperty(IRI.create(BASE + n)); }
    static OWLDataProperty dp(String n) { return df.getOWLDataProperty(IRI.create(BASE + n)); }

    static void faults() {
        Map<String, List<OWLAxiom>> tests = new LinkedHashMap<>();
        tests.put("F1 incident asserted both High and Low severity", Arrays.asList(df.getOWLClassAssertionAxiom(c("LowSeverityIncident"), ind("Incident1"))));
        tests.put("F2 CVSS score outside 0.0-10.0", Arrays.asList(df.getOWLDataPropertyAssertionAxiom(dp("hasCVSSScore"), ind("NewVuln"), df.getOWLLiteral("12.5", df.getOWLDatatype(IRI.create("http://www.w3.org/2001/XMLSchema#decimal"))))));
        tests.put("F3 second, conflicting CVSS score on one vulnerability", Arrays.asList(df.getOWLDataPropertyAssertionAxiom(dp("hasCVSSScore"), ind("UnpatchedDB1"), df.getOWLLiteral("4.0", df.getOWLDatatype(IRI.create("http://www.w3.org/2001/XMLSchema#decimal"))))));
        tests.put("F4 criticality value outside {High, Moderate, Low}", Arrays.asList(df.getOWLDataPropertyAssertionAxiom(dp("hasCriticality"), ind("KioskWS5"), "Critical")));
        tests.put("F5 alert reports an asset instead of an incident (domain/range clash)", Arrays.asList(df.getOWLObjectPropertyAssertionAxiom(op("reportsIncident"), ind("Alert1"), ind("CriticalServer1"))));
        tests.put("F6 ransomware individual whose closure omits T1486", Arrays.asList(
                df.getOWLClassAssertionAxiom(c("RansomwareAttack"), ind("BadRansom")),
                df.getOWLClassAssertionAxiom(df.getOWLObjectAllValuesFrom(op("usesTechnique"), df.getOWLObjectOneOf(ind("T1190"))), ind("BadRansom"))));
        tests.put("F7 a single threat typed as both phishing and DDoS", Arrays.asList(df.getOWLClassAssertionAxiom(c("DDoSAttack"), ind("PhishingAttack2"))));
        tests.put("C1 control: valid new medium-CVSS vulnerability (should stay consistent)", Arrays.asList(df.getOWLDataPropertyAssertionAxiom(dp("hasCVSSScore"), ind("NewVuln2"), df.getOWLLiteral("5.0", df.getOWLDatatype(IRI.create("http://www.w3.org/2001/XMLSchema#decimal")))), df.getOWLClassAssertionAxiom(c("Misconfiguration"), ind("NewVuln2"))));
        for (Map.Entry<String, List<OWLAxiom>> e : tests.entrySet()) {
            for (OWLAxiom ax : e.getValue()) man.addAxiom(ont, ax);
            OWLReasoner rs = fresh();
            boolean cons = rs.isConsistent();
            rs.dispose();
            for (OWLAxiom ax : e.getValue()) man.removeAxiom(ont, ax);
            System.out.println(e.getKey() + "\tconsistent=" + cons);
        }
    }

    static void disjoint() {
        OWLClass h = c("HighSeverityIncident"), m = c("MediumSeverityIncident"), l = c("LowSeverityIncident");
        List<OWLAxiom> rem = new ArrayList<>();
        for (OWLDisjointClassesAxiom ax : ont.getAxioms(AxiomType.DISJOINT_CLASSES))
            if (ax.getClassesInSignature().contains(h)) rem.add(ax);
        for (OWLAxiom ax : rem) man.removeAxiom(ont, ax);
        OWLReasoner rs = fresh();
        System.out.println("removed asserted severity disjointness axioms: " + rem.size());
        System.out.println("High and Medium satisfiable: " + rs.isSatisfiable(df.getOWLObjectIntersectionOf(h, m)));
        System.out.println("High and Low satisfiable: " + rs.isSatisfiable(df.getOWLObjectIntersectionOf(h, l)));
        System.out.println("Medium and Low satisfiable: " + rs.isSatisfiable(df.getOWLObjectIntersectionOf(m, l)));
        System.out.println("High satisfiable: " + rs.isSatisfiable(h) + ", Medium: " + rs.isSatisfiable(m) + ", Low: " + rs.isSatisfiable(l));
        rs.dispose();
    }
}
