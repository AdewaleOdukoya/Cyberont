#!/usr/bin/env python3
"""Generate CyberOnt v2 (OWL 2 DL, Manchester syntax).

v2 extends the v1 ontology (cyberont-v1.ttl, the Protégé file used in the first
draft) with: a standards-grounded severity model (asset criticality per FIPS 199,
CVSS v3.1 qualitative bands, MITRE ATT&CK Impact tactic), ATT&CK technique/tactic
individuals, explicit closure axioms on incident records, top-level disjointness,
datatype range constraints, and eight evaluation scenarios.

Usage: python3 build_v2.py > cyberont-v2.omn
Then:  java -jar robot.jar convert -i cyberont-v2.omn -o cyberont-v2.ttl
"""

BASE = "http://www.semanticweb.org/mac/ontologies/2025/10/cybersecurity/"
ONT = "http://www.semanticweb.org/mac/ontologies/2025/10/cybersecurity"

out = []
w = out.append

w(f"Prefix: : <{BASE}>")
w("Prefix: owl: <http://www.w3.org/2002/07/owl#>")
w("Prefix: rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>")
w("Prefix: rdfs: <http://www.w3.org/2000/01/rdf-schema#>")
w("Prefix: xsd: <http://www.w3.org/2001/XMLSchema#>")
w("Prefix: dcterms: <http://purl.org/dc/terms/>")
w("Prefix: skos: <http://www.w3.org/2004/02/skos/core#>")
w("")
w(f"Ontology: <{ONT}> <{ONT}/2.0.0>")
w('    Annotations: rdfs:label "CyberOnt: Cybersecurity Incident Ontology"@en,')
w('        owl:versionInfo "2.0.0",')
w('        rdfs:comment "Version 2 of the cybersecurity incident ontology. Extends v1 with a standards-grounded, '
  'closure-based severity model (FIPS 199 asset criticality x CVSS v3.1 band / MITRE ATT&CK Impact tactic, '
  'combined following the qualitative risk matrix of NIST SP 800-30 Rev. 1)."@en')
w("")
w("AnnotationProperty: skos:closeMatch")
w("AnnotationProperty: skos:relatedMatch")
w("AnnotationProperty: rdfs:seeAlso")
w("AnnotationProperty: dcterms:source")
w("AnnotationProperty: :alignmentType")
w('    Annotations: rdfs:comment "How the entity relates to an external standard: reused, aligned, extended or new."@en')
w("")

# ---------------------------------------------------------------- properties
def objprop(name, domain, rng, comment, extra=""):
    w(f"ObjectProperty: :{name}")
    w(f'    Annotations: rdfs:comment "{comment}"@en')
    w(f"    Domain: {domain}")
    w(f"    Range: {rng}")
    if extra:
        w("    " + extra)
    w("")

objprop("affectsAsset", ":Incident", ":CyberAsset", "Links an incident to an asset whose confidentiality, integrity or availability it impacts.")
objprop("involvesThreat", ":Incident", ":Threat", "Links an incident to a threat (attack) involved in it.")
objprop("exploitsVulnerability", ":Threat", ":Vulnerability", "Links a threat to a weakness it leverages.")
objprop("targetsAsset", ":Threat", ":CyberAsset", "Links a threat to an asset it targets (v1 name: targetsAssets).")
objprop("causedBy", ":Incident", ":Actor", "Links an incident to the actor responsible for it.")
objprop("protectsAsset", ":SecurityControl", ":CyberAsset", "Links a control to an asset it protects (v1 name: protectsAssets).")
objprop("mitigatesVulnerability", ":SecurityControl", ":Vulnerability", "Links a control to a vulnerability it reduces.")
objprop("mitigatesThreat", ":SecurityControl", ":Threat", "Links a control to a threat it counters.")
objprop("generatedBy", ":Alert", ":SecurityControl", "Links an alert to the sensor or control that raised it.")
objprop("reportsIncident", ":Alert", ":Incident", "Links an alert to the incident it reports.")
objprop("hasVulnerability", ":CyberAsset", ":Vulnerability", "Links an asset to a vulnerability present on it.")
objprop("usesTechnique", ":Threat", ":AttackTechnique", "Links a threat to a MITRE ATT&CK technique it employs.")
objprop("partOfTactic", ":AttackTechnique", ":AttackTactic", "Links an ATT&CK technique to the tactic(s) under which ATT&CK lists it.")

def dataprop(name, domain, rng, comment, functional=False):
    w(f"DataProperty: :{name}")
    w(f'    Annotations: rdfs:comment "{comment}"@en')
    if functional:
        w("    Characteristics: Functional")
    w(f"    Domain: {domain}")
    w(f"    Range: {rng}")
    w("")

dataprop("hasCVSSScore", ":Vulnerability", "xsd:decimal[>= 0.0 , <= 10.0]",
         "CVSS v3.1 base score (0.0-10.0). Functional: one base score per vulnerability record.", True)
dataprop("hasCVSSVector", ":Vulnerability", "xsd:string", "CVSS v3.1 vector string.")
dataprop("hasCVEIdentifier", ":Vulnerability", "xsd:string", "CVE identifier, where one exists.")
dataprop("hasCriticality", ":CyberAsset", '{"High" , "Moderate" , "Low"}',
         "Business criticality of an asset expressed as a FIPS 199 potential-impact level. Functional.", True)
dataprop("hasAttackID", ":AttackTechnique or :AttackTactic", "xsd:string", "MITRE ATT&CK identifier, e.g. T1486 or TA0040.")
dataprop("hasHostname", ":CyberAsset", "xsd:string", "Host name of an asset.")
dataprop("hasIPAddress", ":CyberAsset", "xsd:string", "IP address of an asset.")
dataprop("hasStatus", ":Incident or :Alert", "xsd:string", "Workflow status, e.g. Open or Closed.")
dataprop("hasTimestamp", ":Incident or :Alert", "xsd:dateTime", "Time the incident or alert was recorded (v1 used xsd:string).")

# ---------------------------------------------------------------- classes
def cls(name, sub=None, equiv=None, comment=None, ann=None):
    w(f"Class: :{name}")
    anns = []
    if comment:
        anns.append(f'rdfs:comment "{comment}"@en')
    if ann:
        anns.extend(ann)
    if anns:
        w("    Annotations: " + ",\n        ".join(anns))
    if equiv:
        w(f"    EquivalentTo: {equiv}")
    if sub:
        w(f"    SubClassOf: {sub}")
    w("")

A = lambda t: f':alignmentType "{t}"'
URL = lambda u: f"rdfs:seeAlso <{u}>"

# top level
cls("Actor", comment="An agent involved in a security event.", ann=[A("aligned"), 'skos:closeMatch "STIX 2.1 identity / threat-actor"', 'skos:closeMatch "UCO uco:Attacker (for ThreatActor)"'])
cls("ThreatActor", ":Actor", comment="An actor with malicious intent.", ann=[A("aligned"), 'skos:closeMatch "STIX 2.1 threat-actor SDO"'])
cls("ExternalAttacker", ":ThreatActor", comment="A threat actor outside the organisation.", ann=[A("aligned")])
cls("Insider", ":ThreatActor", comment="A threat actor inside the organisation.", ann=[A("aligned")])
cls("Alert", comment="A notification raised by a security control.", ann=[A("aligned"), 'skos:closeMatch "STIX 2.1 sighting SRO"'])
cls("CyberAsset", comment="Any digital resource of value to the organisation.", ann=[A("aligned"), 'skos:closeMatch "NIST CSF 2.0 ID.AM (asset inventory); STIX 2.1 infrastructure SDO"'])
for c in ["Application", "Database", "NetworkDevice", "Server", "UserAccount", "Workstation"]:
    cls(c, ":CyberAsset", ann=[A("aligned")])
cls("CriticalAsset", equiv=':CyberAsset and (:hasCriticality value "High")',
    comment="Asset whose compromise would have a severe or catastrophic adverse effect (FIPS 199 HIGH). Defined, not tagged (v1 asserted it).",
    ann=[A("extended"), URL("https://doi.org/10.6028/NIST.FIPS.199")])
cls("ModerateCriticalityAsset", equiv=':CyberAsset and (:hasCriticality value "Moderate")', comment="FIPS 199 MODERATE asset.", ann=[A("extended")])
cls("LowCriticalityAsset", equiv=':CyberAsset and (:hasCriticality value "Low")', comment="FIPS 199 LOW asset.", ann=[A("extended")])
cls("NonCriticalAsset", equiv=":ModerateCriticalityAsset or :LowCriticalityAsset", comment="Asset of moderate or low criticality.", ann=[A("new")])

cls("Threat", comment="A realised or attempted malicious activity (an attack).", ann=[A("aligned"), 'skos:closeMatch "UCO uco:Attack; STIX 2.1 attack-pattern SDO"'])
cls("BruteForceAttack", ":Threat and (:usesTechnique value :T1110)", ann=[A("aligned"), URL("https://attack.mitre.org/techniques/T1110/")])
cls("DDoSAttack", ":Threat and (:usesTechnique value :T1498)", ann=[A("aligned"), URL("https://attack.mitre.org/techniques/T1498/")])
cls("MalwareAttack", ":Threat", ann=[A("aligned")])
cls("RansomwareAttack", ":MalwareAttack and (:usesTechnique value :T1486)", ann=[A("aligned"), URL("https://attack.mitre.org/techniques/T1486/")])
cls("TrojanAttack", ":MalwareAttack and (:usesTechnique value :T1204)", ann=[A("aligned"), URL("https://attack.mitre.org/techniques/T1204/")])
cls("PhishingAttack", ":Threat and (:usesTechnique value :T1566)", ann=[A("aligned"), URL("https://attack.mitre.org/techniques/T1566/")])

cls("AttackTactic", comment="A MITRE ATT&CK tactic (adversary goal).", ann=[A("reused"), URL("https://attack.mitre.org/tactics/enterprise/")])
cls("AttackTechnique", comment="A MITRE ATT&CK technique (how a goal is achieved).", ann=[A("reused"), URL("https://attack.mitre.org/techniques/enterprise/")])
cls("ImpactTechnique", equiv=":AttackTechnique and (:partOfTactic value :TA0040)",
    comment="Technique listed under the ATT&CK Impact tactic (TA0040): it directly degrades availability or integrity.", ann=[A("new")])
cls("NonImpactTechnique", equiv=":AttackTechnique and (:partOfTactic only (not ({:TA0040})))",
    comment="Technique none of whose tactics is Impact. Requires a closure axiom on the technique.", ann=[A("new")])

cls("HighImpactThreat", equiv=":Threat and (:usesTechnique some :ImpactTechnique)", comment="Threat employing at least one ATT&CK Impact technique.", ann=[A("new")])
cls("SevereThreat", equiv=":HighImpactThreat or (:Threat and (:exploitsVulnerability some :SevereVulnerability))",
    comment="Threat that has high impact (ATT&CK) or exploits a High/Critical CVSS vulnerability.", ann=[A("new")])
cls("NonSevereThreat", equiv=":Threat and (:usesTechnique only :NonImpactTechnique) and (:exploitsVulnerability only :NonSevereVulnerability)",
    comment="Threat known (under closure) to use no Impact technique and to exploit only Low/Medium CVSS vulnerabilities.", ann=[A("new")])

cls("Vulnerability", comment="A weakness that a threat can exploit.", ann=[A("aligned"), 'skos:closeMatch "UCO uco:Vulnerability; STIX 2.1 vulnerability SDO; CVE record"'])
for c in ["Misconfiguration", "OpenPort", "UnpatchedSoftware", "WeakPassword"]:
    cls(c, ":Vulnerability", ann=[A("aligned")])
cls("SevereVulnerability", equiv=":Vulnerability and (:hasCVSSScore some xsd:decimal[>= 7.0])",
    comment="CVSS v3.1 qualitative rating High (7.0-8.9) or Critical (9.0-10.0).", ann=[A("reused"), URL("https://www.first.org/cvss/v3.1/specification-document")])
cls("CriticalVulnerability", equiv=":Vulnerability and (:hasCVSSScore some xsd:decimal[>= 9.0])", comment="CVSS v3.1 rating Critical.", ann=[A("reused")])
cls("NonSevereVulnerability", equiv=":Vulnerability and (:hasCVSSScore some xsd:decimal[< 7.0])", comment="CVSS v3.1 rating None/Low/Medium (< 7.0).", ann=[A("reused")])

cls("SecurityControl", comment="A technical or organisational safeguard.", ann=[A("aligned"), 'skos:closeMatch "STIX 2.1 course-of-action SDO; NIST SP 800-53 control"'])
for c in ["Antivirus", "BackupSystem", "FirewallRule", "MultiFactorAuthentication", "SecurityAwarenessTraining", "DDoSMitigationService"]:
    cls(c, ":SecurityControl", ann=[A("aligned")])

cls("Incident", comment="An occurrence that jeopardises an asset (NIST SP 800-61).", ann=[A("aligned"), 'skos:closeMatch "STIX 2.1 incident SDO"'])
cls("HighSeverityIncident",
    equiv=":Incident and (:affectsAsset some :CriticalAsset) and (:involvesThreat some :SevereThreat)",
    comment="Matrix cell: critical asset x severe threat.", ann=[A("new")])
cls("MediumSeverityIncident",
    equiv=":Incident and (((:affectsAsset some :CriticalAsset) and (:involvesThreat some :Threat) and (:involvesThreat only :NonSevereThreat)) or "
          "((:affectsAsset only :NonCriticalAsset) and (:affectsAsset some :ModerateCriticalityAsset) and (:involvesThreat some :SevereThreat)))",
    comment="Matrix cells: critical asset x non-severe threat; moderate asset x severe threat.", ann=[A("new")])
cls("LowSeverityIncident",
    equiv=":Incident and (:affectsAsset some :CyberAsset) and (:involvesThreat some :Threat) and ("
          "((:affectsAsset only :NonCriticalAsset) and (:involvesThreat only :NonSevereThreat)) or "
          "((:affectsAsset only :LowCriticalityAsset) and (:involvesThreat some :SevereThreat)))",
    comment="Matrix cells: moderate/low asset x non-severe threat; low asset x severe threat.", ann=[A("new")])

w("DisjointClasses: :Actor, :Alert, :CyberAsset, :Incident, :Threat, :Vulnerability, :AttackTechnique, :AttackTactic")
w("DisjointClasses: :SecurityControl, :Actor, :Alert, :Incident, :Threat, :Vulnerability, :AttackTechnique, :AttackTactic")
w("DisjointClasses: :BruteForceAttack, :DDoSAttack, :MalwareAttack, :PhishingAttack")
w("DisjointClasses: :RansomwareAttack, :TrojanAttack")
w("DisjointClasses: :Misconfiguration, :OpenPort, :UnpatchedSoftware, :WeakPassword")
w("DisjointClasses: :ExternalAttacker, :Insider")
w("DisjointClasses: :CriticalAsset, :ModerateCriticalityAsset, :LowCriticalityAsset")
w("DisjointClasses: :HighSeverityIncident, :MediumSeverityIncident, :LowSeverityIncident")
w("")

# ---------------------------------------------------------------- ATT&CK individuals (reused identifiers)
tactics = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0040": "Impact",
}
techniques = {  # id: (name, [tactics])  -- per MITRE ATT&CK Enterprise
    "T1486": ("Data Encrypted for Impact", ["TA0040"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1498": ("Network Denial of Service", ["TA0040"]),
    "T1110": ("Brute Force", ["TA0006"]),
    "T1566": ("Phishing", ["TA0001"]),
    "T1204": ("User Execution", ["TA0002"]),
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
}
for tid, name in tactics.items():
    w(f"Individual: :{tid}")
    w(f'    Annotations: rdfs:label "{name}"@en, rdfs:seeAlso <https://attack.mitre.org/tactics/{tid}/>')
    w("    Types: :AttackTactic")
    w(f'    Facts: :hasAttackID "{tid}"')
    w("")
for tid, (name, tacs) in techniques.items():
    closure = ", ".join(":" + t for t in tacs)
    w(f"Individual: :{tid}")
    w(f'    Annotations: rdfs:label "{name}"@en, rdfs:seeAlso <https://attack.mitre.org/techniques/{tid}/>')
    w(f"    Types: :AttackTechnique, :partOfTactic only {{{closure}}}")
    w("    Facts: " + ", ".join([f":partOfTactic :{t}" for t in tacs] + [f':hasAttackID "{tid}"']))
    w("")
w("DifferentIndividuals: " + ", ".join(":" + t for t in tactics))
w("")

# ---------------------------------------------------------------- scenario individuals
def ind(name, types, facts=(), comment=None):
    w(f"Individual: :{name}")
    if comment:
        w(f'    Annotations: rdfs:comment "{comment}"@en')
    w("    Types: " + ", ".join(types))
    if facts:
        w("    Facts: " + ",\n        ".join(facts))
    w("")

def only(prop, vals):
    return f":{prop} only {{{', '.join(':' + v for v in vals)}}}" if vals else f":{prop} only owl:Nothing"

def asset(name, typ, crit, host=None, ip=None, vulns=()):
    f = []
    if crit:
        f.append(f':hasCriticality "{crit}"')
    if host:
        f.append(f':hasHostname "{host}"')
    if ip:
        f.append(f':hasIPAddress "{ip}"')
    f += [f":hasVulnerability :{v}" for v in vulns]
    ind(name, [":" + typ], f)

def vuln(name, typ, score=None, vector=None, cve=None):
    f = []
    if score is not None:
        f.append(f"\"{score}\"^^xsd:decimal".join([":hasCVSSScore ", ""]))
    if vector:
        f.append(f':hasCVSSVector "{vector}"')
    if cve:
        f.append(f':hasCVEIdentifier "{cve}"')
    ind(name, [":" + typ], f)

def threat(name, typ, techs, vulns, targets, closed=True):
    types = [":" + typ]
    if closed:
        types += [only("usesTechnique", techs), only("exploitsVulnerability", vulns)]
    f = [f":usesTechnique :{t}" for t in techs] + [f":exploitsVulnerability :{v}" for v in vulns] + [f":targetsAsset :{a}" for a in targets]
    ind(name, types, f)

def incident(name, assets, threats, actor, status, ts, closed=True, comment=None):
    types = [":Incident"]
    if closed:
        types += [only("affectsAsset", assets), only("involvesThreat", threats)]
    f = [f":affectsAsset :{a}" for a in assets] + [f":involvesThreat :{t}" for t in threats]
    if actor:
        f.append(f":causedBy :{actor}")
    f += [f':hasStatus "{status}"', f':hasTimestamp "{ts}"^^xsd:dateTime']
    ind(name, types, f, comment)

# Actors
ind("Attacker1", [":ExternalAttacker"])
ind("Insider6", [":Insider"])

# S1 Ransomware on critical database server (v1 case study, retained)
vuln("UnpatchedDB1", "UnpatchedSoftware", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
asset("CriticalServer1", "Server", "High", "prod-db-01", "10.0.0.10", ["UnpatchedDB1"])
threat("RansomwareAttack1", "RansomwareAttack", ["T1190", "T1486", "T1490"], ["UnpatchedDB1"], ["CriticalServer1"])
incident("Incident1", ["CriticalServer1"], ["RansomwareAttack1"], "Attacker1", "Open", "2025-11-24T09:30:00Z",
         comment="S1: ransomware against the production database server (v1 case study).")
ind("BackupSystem1", [":BackupSystem"], [":protectsAsset :CriticalServer1", ":mitigatesThreat :RansomwareAttack1"])
ind("EDR1", [":Antivirus"], [":protectsAsset :CriticalServer1"])
ind("Alert1", [":Alert"], [":generatedBy :EDR1", ":reportsIncident :Incident1", ':hasStatus "Open"', ':hasTimestamp "2025-11-24T09:28:00Z"^^xsd:dateTime'])

# S2 Phishing against a finance workstation (moderate) - macro misconfiguration
vuln("MacroPolicy2", "Misconfiguration", 7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
asset("FinanceWS2", "Workstation", "Moderate", "fin-ws-12", "10.0.2.12", ["MacroPolicy2"])
threat("PhishingAttack2", "PhishingAttack", ["T1566", "T1204"], ["MacroPolicy2"], ["FinanceWS2"])
incident("Incident2", ["FinanceWS2"], ["PhishingAttack2"], "Attacker1", "Open", "2025-11-25T08:10:00Z",
         comment="S2: phishing e-mail with a malicious macro against a finance workstation.")
ind("AwarenessTraining2", [":SecurityAwarenessTraining"], [":mitigatesThreat :PhishingAttack2"])
ind("MailGateway2", [":FirewallRule"], [":protectsAsset :FinanceWS2", ":mitigatesVulnerability :MacroPolicy2"])

# S3 Brute force against a privileged account (critical) - weak password, medium CVSS
vuln("WeakPassword3", "WeakPassword", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
asset("AdminAccount3", "UserAccount", "High", vulns=["WeakPassword3"])
threat("BruteForceAttack3", "BruteForceAttack", ["T1110", "T1078"], ["WeakPassword3"], ["AdminAccount3"])
incident("Incident3", ["AdminAccount3"], ["BruteForceAttack3"], "Attacker1", "Open", "2025-11-26T02:45:00Z",
         comment="S3: password brute force against a database administrator account.")
ind("MFA3", [":MultiFactorAuthentication"], [":protectsAsset :AdminAccount3", ":mitigatesVulnerability :WeakPassword3", ":mitigatesThreat :BruteForceAttack3"])
ind("Alert3", [":Alert"], [":generatedBy :MFA3", ":reportsIncident :Incident3", ':hasStatus "Open"', ':hasTimestamp "2025-11-26T02:44:00Z"^^xsd:dateTime'])

# S4 DDoS against the customer portal (critical) - no CVE involved
asset("WebPortal4", "Application", "High", "portal.example.com", "203.0.113.4")
threat("DDoSAttack4", "DDoSAttack", ["T1498"], [], ["WebPortal4"])
incident("Incident4", ["WebPortal4"], ["DDoSAttack4"], "Attacker1", "Open", "2025-11-27T13:00:00Z",
         comment="S4: volumetric DDoS against the customer-facing portal.")
ind("DDoSShield4", [":DDoSMitigationService"], [":protectsAsset :WebPortal4", ":mitigatesThreat :DDoSAttack4"])
ind("Alert4", [":Alert"], [":generatedBy :DDoSShield4", ":reportsIncident :Incident4", ':hasStatus "Open"', ':hasTimestamp "2025-11-27T12:58:00Z"^^xsd:dateTime'])

# S5 Trojan on a low-criticality kiosk - high CVSS browser flaw
vuln("UnpatchedBrowser5", "UnpatchedSoftware", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
asset("KioskWS5", "Workstation", "Low", "lobby-kiosk-01", "10.0.9.5", ["UnpatchedBrowser5"])
threat("TrojanAttack5", "TrojanAttack", ["T1204"], ["UnpatchedBrowser5"], ["KioskWS5"])
incident("Incident5", ["KioskWS5"], ["TrojanAttack5"], "Attacker1", "Closed", "2025-11-28T10:20:00Z",
         comment="S5: trojan executed on a lobby kiosk with an unpatched browser.")
ind("AV5", [":Antivirus"], [":protectsAsset :KioskWS5", ":mitigatesThreat :TrojanAttack5"])

# S6 Brute force against a test server (moderate) - by an insider
vuln("OpenSSH6", "OpenPort", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
vuln("WeakPassword6", "WeakPassword", 4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")
asset("TestServer6", "Server", "Moderate", "test-app-03", "10.0.5.3", ["OpenSSH6", "WeakPassword6"])
threat("BruteForceAttack6", "BruteForceAttack", ["T1110"], ["OpenSSH6", "WeakPassword6"], ["TestServer6"])
incident("Incident6", ["TestServer6"], ["BruteForceAttack6"], "Insider6", "Closed", "2025-11-29T22:05:00Z",
         comment="S6: SSH password guessing against a test server by an insider.")
ind("Firewall6", [":FirewallRule"], [":protectsAsset :TestServer6", ":mitigatesVulnerability :OpenSSH6"])

# S7 Multi-stage: brute force followed by ransomware on a critical file server
vuln("WeakPassword7", "WeakPassword", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
vuln("UnpatchedSMB7", "UnpatchedSoftware", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
asset("FileServer7", "Server", "High", "fs-01", "10.0.0.20", ["WeakPassword7", "UnpatchedSMB7"])
threat("BruteForceAttack7", "BruteForceAttack", ["T1110"], ["WeakPassword7"], ["FileServer7"])
threat("RansomwareAttack7", "RansomwareAttack", ["T1486"], ["UnpatchedSMB7"], ["FileServer7"])
incident("Incident7", ["FileServer7"], ["BruteForceAttack7", "RansomwareAttack7"], "Attacker1", "Open", "2025-11-30T04:15:00Z",
         comment="S7: multi-stage incident (brute force, then ransomware) on a critical file server.")
ind("BackupSystem7", [":BackupSystem"], [":protectsAsset :FileServer7", ":mitigatesThreat :RansomwareAttack7"])

# S8 Incomplete record: unknown malware, asset criticality not recorded, no closure
asset("DevWS8", "Workstation", None, "dev-ws-08", "10.0.7.8")
threat("MalwareAttack8", "MalwareAttack", [], [], ["DevWS8"], closed=False)
incident("Incident8", ["DevWS8"], ["MalwareAttack8"], None, "Open", "2025-12-01T11:00:00Z", closed=False,
         comment="S8: incomplete record - unknown malware, criticality not recorded, record not closed.")

print("\n".join(out))
