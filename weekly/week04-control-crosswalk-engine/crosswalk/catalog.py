"""Reference catalogs for the four frameworks the engine crosswalks.

Only requirement identifiers and short titles are included. The titles for
ISO/IEC 27001 Annex A are the published control names; SOC 2 titles are short
paraphrases written for this tool (the AICPA criteria text is not reproduced);
CIS Controls safeguards are listed by number with their parent control name.

Catalog versions:
    ISO27001  ISO/IEC 27001:2022 (clauses 4-10 and the 93 Annex A controls)
    SOC2      AICPA Trust Services Criteria 2017 (revised points of focus 2022):
              Common Criteria (Security), Availability and Confidentiality
    CSF2      NIST Cybersecurity Framework 2.0 (106 subcategories)
    CIS8      CIS Critical Security Controls v8.1 (153 safeguards, IG1 tagged)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Requirement:
    """One requirement (control, criterion, subcategory or safeguard) in a framework."""

    framework: str
    req_id: str
    title: str
    groups: frozenset[str] = field(default_factory=frozenset)


@dataclass
class Framework:
    """A framework catalog: id, display name and its requirements, in catalog order."""

    key: str
    name: str
    requirements: dict[str, Requirement]

    def group_members(self, group: str) -> list[str]:
        """Requirement ids belonging to a named scope group ('all' returns everything)."""
        if group.lower() == "all":
            return list(self.requirements)
        return [r.req_id for r in self.requirements.values() if group.lower() in r.groups]

    @property
    def groups(self) -> list[str]:
        seen: list[str] = []
        for r in self.requirements.values():
            for g in sorted(r.groups):
                if g not in seen:
                    seen.append(g)
        return seen


# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022
# ---------------------------------------------------------------------------
ISO_CLAUSES: dict[str, str] = {
    "4.1": "Understanding the organization and its context",
    "4.2": "Needs and expectations of interested parties",
    "4.3": "Scope of the ISMS",
    "4.4": "Information security management system",
    "5.1": "Leadership and commitment",
    "5.2": "Information security policy",
    "5.3": "Organizational roles, responsibilities and authorities",
    "6.1.1": "Actions to address risks and opportunities: general",
    "6.1.2": "Information security risk assessment (process)",
    "6.1.3": "Information security risk treatment (process, SoA)",
    "6.2": "Information security objectives and planning",
    "6.3": "Planning of changes",
    "7.1": "Resources",
    "7.2": "Competence",
    "7.3": "Awareness",
    "7.4": "Communication",
    "7.5.1": "Documented information: general",
    "7.5.2": "Creating and updating documented information",
    "7.5.3": "Control of documented information",
    "8.1": "Operational planning and control",
    "8.2": "Information security risk assessment (performed)",
    "8.3": "Information security risk treatment (implemented)",
    "9.1": "Monitoring, measurement, analysis and evaluation",
    "9.2.1": "Internal audit: general",
    "9.2.2": "Internal audit programme",
    "9.3.1": "Management review: general",
    "9.3.2": "Management review inputs",
    "9.3.3": "Management review results",
    "10.1": "Continual improvement",
    "10.2": "Nonconformity and corrective action",
}

_ANNEX_A_RAW: dict[str, str] = {
    # 5 Organizational controls
    "5.1": "Policies for information security",
    "5.2": "Information security roles and responsibilities",
    "5.3": "Segregation of duties",
    "5.4": "Management responsibilities",
    "5.5": "Contact with authorities",
    "5.6": "Contact with special interest groups",
    "5.7": "Threat intelligence",
    "5.8": "Information security in project management",
    "5.9": "Inventory of information and other associated assets",
    "5.10": "Acceptable use of information and other associated assets",
    "5.11": "Return of assets",
    "5.12": "Classification of information",
    "5.13": "Labelling of information",
    "5.14": "Information transfer",
    "5.15": "Access control",
    "5.16": "Identity management",
    "5.17": "Authentication information",
    "5.18": "Access rights",
    "5.19": "Information security in supplier relationships",
    "5.20": "Addressing information security within supplier agreements",
    "5.21": "Managing information security in the ICT supply chain",
    "5.22": "Monitoring, review and change management of supplier services",
    "5.23": "Information security for use of cloud services",
    "5.24": "Information security incident management planning and preparation",
    "5.25": "Assessment and decision on information security events",
    "5.26": "Response to information security incidents",
    "5.27": "Learning from information security incidents",
    "5.28": "Collection of evidence",
    "5.29": "Information security during disruption",
    "5.30": "ICT readiness for business continuity",
    "5.31": "Legal, statutory, regulatory and contractual requirements",
    "5.32": "Intellectual property rights",
    "5.33": "Protection of records",
    "5.34": "Privacy and protection of PII",
    "5.35": "Independent review of information security",
    "5.36": "Compliance with policies, rules and standards for information security",
    "5.37": "Documented operating procedures",
    # 6 People controls
    "6.1": "Screening",
    "6.2": "Terms and conditions of employment",
    "6.3": "Information security awareness, education and training",
    "6.4": "Disciplinary process",
    "6.5": "Responsibilities after termination or change of employment",
    "6.6": "Confidentiality or non-disclosure agreements",
    "6.7": "Remote working",
    "6.8": "Information security event reporting",
    # 7 Physical controls
    "7.1": "Physical security perimeters",
    "7.2": "Physical entry",
    "7.3": "Securing offices, rooms and facilities",
    "7.4": "Physical security monitoring",
    "7.5": "Protecting against physical and environmental threats",
    "7.6": "Working in secure areas",
    "7.7": "Clear desk and clear screen",
    "7.8": "Equipment siting and protection",
    "7.9": "Security of assets off-premises",
    "7.10": "Storage media",
    "7.11": "Supporting utilities",
    "7.12": "Cabling security",
    "7.13": "Equipment maintenance",
    "7.14": "Secure disposal or re-use of equipment",
    # 8 Technological controls
    "8.1": "User endpoint devices",
    "8.2": "Privileged access rights",
    "8.3": "Information access restriction",
    "8.4": "Access to source code",
    "8.5": "Secure authentication",
    "8.6": "Capacity management",
    "8.7": "Protection against malware",
    "8.8": "Management of technical vulnerabilities",
    "8.9": "Configuration management",
    "8.10": "Information deletion",
    "8.11": "Data masking",
    "8.12": "Data leakage prevention",
    "8.13": "Information backup",
    "8.14": "Redundancy of information processing facilities",
    "8.15": "Logging",
    "8.16": "Monitoring activities",
    "8.17": "Clock synchronization",
    "8.18": "Use of privileged utility programs",
    "8.19": "Installation of software on operational systems",
    "8.20": "Networks security",
    "8.21": "Security of network services",
    "8.22": "Segregation of networks",
    "8.23": "Web filtering",
    "8.24": "Use of cryptography",
    "8.25": "Secure development life cycle",
    "8.26": "Application security requirements",
    "8.27": "Secure system architecture and engineering principles",
    "8.28": "Secure coding",
    "8.29": "Security testing in development and acceptance",
    "8.30": "Outsourced development",
    "8.31": "Separation of development, test and production environments",
    "8.32": "Change management",
    "8.33": "Test information",
    "8.34": "Protection of information systems during audit testing",
}

# ---------------------------------------------------------------------------
# SOC 2 Trust Services Criteria (paraphrased short titles)
# ---------------------------------------------------------------------------
SOC2_CRITERIA: dict[str, str] = {
    "CC1.1": "Commitment to integrity and ethical values",
    "CC1.2": "Board independence and oversight of internal control",
    "CC1.3": "Structures, reporting lines and authorities",
    "CC1.4": "Commitment to attract, develop and retain competent people",
    "CC1.5": "Individuals held accountable for internal control",
    "CC2.1": "Relevant, quality information supports internal control",
    "CC2.2": "Internal communication of objectives and responsibilities",
    "CC2.3": "Communication with external parties",
    "CC3.1": "Objectives specified clearly enough to identify risks",
    "CC3.2": "Risks identified and analysed",
    "CC3.3": "Potential for fraud considered",
    "CC3.4": "Significant changes identified and assessed",
    "CC4.1": "Ongoing and/or separate evaluations of controls",
    "CC4.2": "Deficiencies evaluated and communicated",
    "CC5.1": "Control activities selected and developed",
    "CC5.2": "General controls over technology",
    "CC5.3": "Controls deployed through policies and procedures",
    "CC6.1": "Logical access security over protected information assets",
    "CC6.2": "Users registered and authorised before access is granted",
    "CC6.3": "Access modified and removed; least privilege and segregation",
    "CC6.4": "Physical access to facilities and assets restricted",
    "CC6.5": "Protection maintained until assets are disposed of",
    "CC6.6": "Protection against threats from outside system boundaries",
    "CC6.7": "Transmission and movement of information restricted and protected",
    "CC6.8": "Unauthorised or malicious software prevented or detected",
    "CC7.1": "Configuration changes and new vulnerabilities detected",
    "CC7.2": "System components monitored for anomalies",
    "CC7.3": "Security events evaluated to determine if they are incidents",
    "CC7.4": "Incidents responded to under a defined programme",
    "CC7.5": "Recovery from identified incidents",
    "CC8.1": "Changes authorised, designed, tested, approved and implemented",
    "CC9.1": "Risk mitigation for business disruption",
    "CC9.2": "Vendor and business partner risk managed",
    "A1.1": "Capacity managed to meet objectives",
    "A1.2": "Environmental protections, backup and recovery infrastructure",
    "A1.3": "Recovery plan procedures tested",
    "C1.1": "Confidential information identified and protected",
    "C1.2": "Confidential information disposed of",
}

# ---------------------------------------------------------------------------
# NIST CSF 2.0: categories and subcategory numbers (gaps are withdrawn ids)
# ---------------------------------------------------------------------------
CSF_CATEGORIES: dict[str, tuple[str, tuple[int, ...]]] = {
    "GV.OC": ("Organizational Context", (1, 2, 3, 4, 5)),
    "GV.RM": ("Risk Management Strategy", (1, 2, 3, 4, 5, 6, 7)),
    "GV.RR": ("Roles, Responsibilities, and Authorities", (1, 2, 3, 4)),
    "GV.PO": ("Policy", (1, 2)),
    "GV.OV": ("Oversight", (1, 2, 3)),
    "GV.SC": ("Cybersecurity Supply Chain Risk Management", tuple(range(1, 11))),
    "ID.AM": ("Asset Management", (1, 2, 3, 4, 5, 7, 8)),
    "ID.RA": ("Risk Assessment", tuple(range(1, 11))),
    "ID.IM": ("Improvement", (1, 2, 3, 4)),
    "PR.AA": ("Identity Management, Authentication, and Access Control", (1, 2, 3, 4, 5, 6)),
    "PR.AT": ("Awareness and Training", (1, 2)),
    "PR.DS": ("Data Security", (1, 2, 10, 11)),
    "PR.PS": ("Platform Security", (1, 2, 3, 4, 5, 6)),
    "PR.IR": ("Technology Infrastructure Resilience", (1, 2, 3, 4)),
    "DE.CM": ("Continuous Monitoring", (1, 2, 3, 6, 9)),
    "DE.AE": ("Adverse Event Analysis", (2, 3, 4, 6, 7, 8)),
    "RS.MA": ("Incident Management", (1, 2, 3, 4, 5)),
    "RS.AN": ("Incident Analysis", (3, 6, 7, 8)),
    "RS.CO": ("Incident Response Reporting and Communication", (2, 3)),
    "RS.MI": ("Incident Mitigation", (1, 2)),
    "RC.RP": ("Incident Recovery Plan Execution", (1, 2, 3, 4, 5, 6)),
    "RC.CO": ("Incident Recovery Communication", (3, 4)),
}
CSF_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect",
                 "RS": "Respond", "RC": "Recover"}

# ---------------------------------------------------------------------------
# CIS Controls v8.1: control names, safeguard counts and Implementation Group 1
# ---------------------------------------------------------------------------
CIS_CONTROLS: dict[int, tuple[str, int]] = {
    1: ("Inventory and Control of Enterprise Assets", 5),
    2: ("Inventory and Control of Software Assets", 7),
    3: ("Data Protection", 14),
    4: ("Secure Configuration of Enterprise Assets and Software", 12),
    5: ("Account Management", 6),
    6: ("Access Control Management", 8),
    7: ("Continuous Vulnerability Management", 7),
    8: ("Audit Log Management", 12),
    9: ("Email and Web Browser Protections", 7),
    10: ("Malware Defenses", 7),
    11: ("Data Recovery", 5),
    12: ("Network Infrastructure Management", 8),
    13: ("Network Monitoring and Defense", 11),
    14: ("Security Awareness and Skills Training", 9),
    15: ("Service Provider Management", 7),
    16: ("Application Software Security", 14),
    17: ("Incident Response Management", 9),
    18: ("Penetration Testing", 5),
}
CIS_IG1: frozenset[str] = frozenset("""
1.1 1.2 2.1 2.2 2.3 3.1 3.2 3.3 3.4 3.5 3.6 4.1 4.2 4.3 4.4 4.5 4.6 4.7
5.1 5.2 5.3 5.4 6.1 6.2 6.3 6.4 6.5 7.1 7.2 7.3 7.4 8.1 8.2 8.3 9.1 9.2
10.1 10.2 10.3 11.1 11.2 11.3 11.4 12.1 14.1 14.2 14.3 14.4 14.5 14.6 14.7 14.8
15.1 17.1 17.2 17.3
""".split())


# ---------------------------------------------------------------------------
# Build the catalogs
# ---------------------------------------------------------------------------
def _build_iso() -> Framework:
    reqs: dict[str, Requirement] = {}
    for cid, title in ISO_CLAUSES.items():
        reqs[cid] = Requirement("ISO27001", cid, title, frozenset({"clauses", f"clause{cid.split('.')[0]}"}))
    for cid, title in _ANNEX_A_RAW.items():
        rid = f"A.{cid}"
        reqs[rid] = Requirement("ISO27001", rid, title, frozenset({"annex_a", f"a.{cid.split('.')[0]}"}))
    return Framework("ISO27001", "ISO/IEC 27001:2022", reqs)


def _build_soc2() -> Framework:
    reqs = {}
    for cid, title in SOC2_CRITERIA.items():
        series = re.match(r"[A-Z]+\d?", cid).group(0)  # CC1, A1, C1
        family = "cc" if cid.startswith("CC") else series.lower()
        reqs[cid] = Requirement("SOC2", cid, title, frozenset({family, series.lower()}))
    return Framework("SOC2", "SOC 2 (TSC 2017)", reqs)


def _build_csf() -> Framework:
    reqs = {}
    for cat, (name, numbers) in CSF_CATEGORIES.items():
        fn = cat.split(".")[0]
        for n in numbers:
            rid = f"{cat}-{n:02d}"
            reqs[rid] = Requirement("CSF2", rid, name, frozenset({fn.lower(), cat.lower()}))
    return Framework("CSF2", "NIST CSF 2.0", reqs)


def _build_cis() -> Framework:
    reqs = {}
    for ctl, (name, count) in CIS_CONTROLS.items():
        for n in range(1, count + 1):
            rid = f"{ctl}.{n}"
            groups = {f"control{ctl}"} | ({"ig1"} if rid in CIS_IG1 else set())
            reqs[rid] = Requirement("CIS8", rid, name, frozenset(groups))
    return Framework("CIS8", "CIS Controls v8.1", reqs)


FRAMEWORKS: dict[str, Framework] = {f.key: f for f in (_build_iso(), _build_soc2(), _build_csf(), _build_cis())}

FRAMEWORK_ALIASES = {
    "ISO": "ISO27001", "ISO27001": "ISO27001", "ISO27K": "ISO27001", "27001": "ISO27001",
    "SOC2": "SOC2", "SOC": "SOC2", "TSC": "SOC2",
    "CSF": "CSF2", "CSF2": "CSF2", "NISTCSF": "CSF2", "NIST": "CSF2",
    "CIS": "CIS8", "CIS8": "CIS8", "CISV8": "CIS8",
}


def framework_key(name: str) -> str | None:
    """Resolve a framework name or alias ('iso', 'NIST-CSF', 'cis v8') to its catalog key."""
    return FRAMEWORK_ALIASES.get(re.sub(r"[^A-Z0-9]", "", name.upper()))


def normalize_id(framework: str, raw: str) -> str:
    """Normalise a requirement id as typed in a spreadsheet into catalog form.

    'pr.aa-1' -> 'PR.AA-01', 'CIS 5.1' -> '5.1', 'a.8.15' -> 'A.8.15', 'cc6.1' -> 'CC6.1'.
    No guessing beyond formatting: ISO '8.15' stays a clause id and is reported if unknown.
    """
    s = raw.strip().upper().replace(" ", "")
    if framework == "CSF2":
        m = re.fullmatch(r"([A-Z]{2})\.([A-Z]{2})-0*(\d{1,2})", s)
        if m:
            return f"{m.group(1)}.{m.group(2)}-{int(m.group(3)):02d}"
    elif framework == "CIS8":
        s = re.sub(r"^(CIS|SAFEGUARD)", "", s)
    elif framework == "ISO27001":
        s = re.sub(r"^ANNEXA", "A", s)
        s = re.sub(r"^A(?=\d)", "A.", s)
    return s


def hint_for_unknown(framework: str, req_id: str) -> str:
    """Explain the most likely reason an id is not in the catalog (legacy versions, typos)."""
    if framework == "ISO27001":
        if re.fullmatch(r"A\.(9|1[0-8])\.\d+(\.\d+)?|A\.\d+\.\d+\.\d+", req_id):
            return "looks like ISO/IEC 27001:2013 numbering; map it to the 2022 control"
        if re.fullmatch(r"[5-8]\.\d+", req_id) and f"A.{req_id}" in FRAMEWORKS["ISO27001"].requirements:
            return f"clause {req_id} does not exist; did you mean Annex A control A.{req_id}?"
    if framework == "CSF2":
        if re.fullmatch(r"(ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+", req_id):
            cat = req_id.split("-")[0]
            if cat in {"PR.AC", "PR.IP", "PR.PT", "PR.MA", "DE.DP", "RS.RP", "RS.IM", "RC.IM",
                       "ID.BE", "ID.GV", "ID.SC"}:
                return f"{cat} is a CSF 1.1 category that CSF 2.0 removed; remap to the 2.0 subcategory"
            return "subcategory does not exist in CSF 2.0 (withdrawn or renumbered)"
    if framework == "CIS8":
        m = re.fullmatch(r"(\d+)\.(\d+)", req_id)
        if m and int(m.group(1)) in CIS_CONTROLS:
            name, count = CIS_CONTROLS[int(m.group(1))]
            return f"CIS Control {m.group(1)} has safeguards {m.group(1)}.1-{m.group(1)}.{count} in v8.1"
        if m:
            return "CIS Controls v8.1 has controls 1-18"
    if framework == "SOC2" and re.fullmatch(r"(CC|A|C|PI|P)\d+\.\d+", req_id):
        return "not one of the Security, Availability or Confidentiality criteria in this catalog"
    return "not in the catalog"


def describe(framework: str, req_id: str) -> str:
    """Human-readable label such as 'A.8.15 Logging' or 'CIS 8.2 (Audit Log Management)'."""
    fw = FRAMEWORKS[framework]
    req = fw.requirements.get(req_id)
    if req is None:
        return req_id
    if framework == "CIS8":
        return f"CIS {req_id} ({req.title})"
    return f"{req_id} {req.title}"


assert len(FRAMEWORKS["ISO27001"].requirements) == 30 + 93
assert len(FRAMEWORKS["CSF2"].requirements) == 106, "NIST CSF 2.0 has 106 subcategories"
assert len(FRAMEWORKS["CIS8"].requirements) == 153, "CIS Controls v8.1 has 153 safeguards"
assert len(CIS_IG1) == 56, "CIS IG1 has 56 safeguards"
