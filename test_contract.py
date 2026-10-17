"""Local logic tests for contract.py using a small simulated GenLayer runtime.

AI answers are authored fixtures, not live AI. These tests check the contract's
deterministic behaviour (roles, lifecycle, hash sign-off, quote checks,
validator agreement, severity rules, officer records), not the model's judgement.
Run: python -m pytest test_contract.py -q
"""
import json
import sys
import types
from pathlib import Path

import pytest

SUPERVISOR = "0x" + "a" * 40
OFFICER = "0x" + "b" * 40
OUTSIDER = "0x" + "c" * 40

REPORT = ("Officer: A. Khan, ID 4471. Date: 2 April 2026, 15:10. Location: Northgate Shopping Centre, "
          "unit 12. A male concealed two bottles of perfume and walked past the tills. I stopped him at "
          "the exit; he dropped the items and ran. I informed the control room and the police were called.")
VAGUE = "I saw a man acting suspiciously earlier tonight. I asked him to leave and he walked off."

FACTS = ["who", "what", "when", "where", "actions", "weapon", "threat_to_life",
         "injury", "police", "loss_or_damage", "crime_attempt"]


class UserError(Exception):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class Addr:
    def __init__(self, h):
        self.as_hex = h


def answers(**ys):
    """Build an AI answer: ys maps fact -> quote for each Y; everything else is N."""
    return {"facts": [{"fact": f, "answer": "Y" if f in ys else "N", "quote": ys.get(f, "")} for f in FACTS]}


FULL_HIGH = answers(who="Officer: A. Khan, ID 4471", what="A male concealed two bottles of perfume",
                    when="Date: 2 April 2026, 15:10", where="Northgate Shopping Centre, unit 12",
                    actions="I informed the control room", police="the police were called",
                    crime_attempt="concealed two bottles of perfume and walked past the tills")
VAGUE_ANS = answers(what="I saw a man acting suspiciously")


class Sim:
    def __init__(self):
        self.sender = SUPERVISOR
        self.leader_answer = None
        self.validator_answer = None
        self.audit = True
        self.in_validator = False
        self.prompts = []

    def build_gl(self):
        sim = self
        gl = types.SimpleNamespace()
        gl.vm = types.SimpleNamespace(UserError=UserError, Return=Return)
        gl.public = types.SimpleNamespace(write=lambda f: f, view=lambda f: f)
        gl.Contract = object

        class Msg:
            @property
            def sender_address(self):
                return Addr(sim.sender)
        gl.message = Msg()

        def exec_prompt(prompt, response_format=None):
            sim.prompts.append(prompt)
            if prompt.startswith("Audit the proposed"):
                return {"accept": sim.audit}
            ans = sim.validator_answer if (sim.in_validator and sim.validator_answer is not None) else sim.leader_answer
            return ans(prompt) if callable(ans) else ans
        gl.nondet = types.SimpleNamespace(exec_prompt=exec_prompt)

        def run_nondet_unsafe(leader_fn, validator_fn):
            sim.in_validator = False
            out = leader_fn()
            sim.in_validator = True
            try:
                ok = validator_fn(Return(out))
            finally:
                sim.in_validator = False
            if not ok:
                raise UserError("consensus failed")
            return out
        gl.vm.run_nondet_unsafe = run_nondet_unsafe
        return gl


@pytest.fixture
def env():
    sim = Sim()
    mod = types.ModuleType("genlayer")
    mod.gl = sim.build_gl()
    mod.TreeMap = dict
    mod.u256 = int
    sys.modules["genlayer"] = mod
    src = Path(__file__).with_name("contract.py").read_text()
    src = src.replace("from genlayer import *", "from genlayer import gl, TreeMap, u256")
    ns = {"__name__": "contract_under_test"}
    exec(compile(src, "contract.py", "exec"), ns)
    C = ns["SecurityIncidentLog"]
    c = C.__new__(C)
    c.sites, c.reports, c.officer_records, c.demo_results = {}, {}, {}, {}
    c.__init__()
    return sim, c, ns


def setup_site(sim, c):
    sim.sender = SUPERVISOR
    c.register_site("Northgate Shopping Centre")
    c.add_officer(0, OFFICER)


def summary(c, rid=0):
    return json.loads(c.get_report_summary(rid))


# ---------- happy path ----------

def test_full_lifecycle_high_incident(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    sim.leader_answer = FULL_HIGH
    sim.sender = OUTSIDER
    c.assess(0)
    s = summary(c)
    assert s["status"] == "AWAITING_SIGN_OFF"
    assert s["severity"] == "HIGH" and s["escalation_required"] is True and s["missing"] == []
    sim.sender = SUPERVISOR
    with pytest.raises(UserError):
        c.sign_off(0, s["report_hash"], "ok")  # HIGH needs a proper note
    c.sign_off(0, s["report_hash"], "Police reference requested and store manager briefed.")
    assert summary(c)["status"] == "CLOSED"
    rec = json.loads(c.get_officer_record(OFFICER))
    assert rec == {"officer": OFFICER, "closed": 1, "sent_back": 0, "complete_first_time": 1}
    site = json.loads(c.get_site(0))
    assert site["stats"]["closed"] == 1 and site["stats"]["HIGH"] == 1


def test_incomplete_report_sent_back_then_amended(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, VAGUE)
    first_hash = summary(c)["report_hash"]
    sim.leader_answer = VAGUE_ANS
    c.assess(0)
    s = summary(c)
    assert s["status"] == "NEEDS_AMENDMENT"
    assert s["missing"] == ["who", "when", "where", "actions"]
    c.amend_report(0, REPORT)
    s = summary(c)
    assert s["status"] == "SUBMITTED" and s["versions"] == 2 and s["report_hash"] != first_hash
    sim.leader_answer = FULL_HIGH
    c.assess(0)
    sim.sender = SUPERVISOR
    c.sign_off(0, summary(c)["report_hash"], "Police reference requested and logged.")
    rec = json.loads(c.get_officer_record(OFFICER))
    assert rec["sent_back"] == 1 and rec["closed"] == 1 and rec["complete_first_time"] == 0


def test_review_reassesses_once(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    sim.leader_answer = FULL_HIGH
    c.assess(0)
    c.request_review(0, "The goods were recovered, please re-check the loss answer.")
    assert summary(c)["status"] == "UNDER_REVIEW"
    c.assess(0)
    assert summary(c)["status"] == "AWAITING_SIGN_OFF" and summary(c)["assessments"] == 2
    assert "please re-check the loss answer" in sim.prompts[-2]
    with pytest.raises(UserError):
        c.request_review(0, "A second review should be rejected.")


# ---------- roles and consent ----------

def test_officer_and_supervisor_must_differ(env):
    sim, c, _ = env
    c.register_site("Riverside Retail Park")
    with pytest.raises(UserError):
        c.add_officer(0, SUPERVISOR)


def test_only_supervisor_adds_officers(env):
    sim, c, _ = env
    c.register_site("Riverside Retail Park")
    sim.sender = OUTSIDER
    with pytest.raises(UserError):
        c.add_officer(0, OFFICER)


def test_only_site_officers_file(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OUTSIDER
    with pytest.raises(UserError):
        c.file_report(0, REPORT)


def test_sign_off_needs_exact_hash_and_supervisor(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    sim.leader_answer = FULL_HIGH
    c.assess(0)
    h = summary(c)["report_hash"]
    with pytest.raises(UserError):
        c.sign_off(0, h, "Officer trying to sign off their own report.")
    sim.sender = SUPERVISOR
    with pytest.raises(UserError):
        c.sign_off(0, "wronghash", "Police reference requested and logged.")


def test_only_filing_officer_amends(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, VAGUE)
    sim.leader_answer = VAGUE_ANS
    c.assess(0)
    sim.sender = OUTSIDER
    with pytest.raises(UserError):
        c.amend_report(0, REPORT)


def test_amendment_limit(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, VAGUE)
    sim.leader_answer = VAGUE_ANS
    for _ in range(3):
        c.assess(0)
        c.amend_report(0, VAGUE + " Still vague.")
    c.assess(0)
    with pytest.raises(UserError):
        c.amend_report(0, REPORT)


def test_cannot_assess_closed_or_twice(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    sim.leader_answer = FULL_HIGH
    c.assess(0)
    with pytest.raises(UserError):
        c.assess(0)


# ---------- consensus and AI-output checks ----------

def test_validator_disagreement_blocks_and_changes_nothing(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    before = c.get_report(0)
    sim.leader_answer = FULL_HIGH
    no_police = json.loads(json.dumps(FULL_HIGH))
    for e in no_police["facts"]:
        if e["fact"] == "police":
            e["answer"], e["quote"] = "N", ""
    sim.validator_answer = no_police  # HIGH vs MEDIUM
    with pytest.raises(UserError):
        c.assess(0)
    assert c.get_report(0) == before


def test_same_outcome_different_wording_agrees(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    sim.leader_answer = FULL_HIGH
    alt = json.loads(json.dumps(FULL_HIGH))
    for e in alt["facts"]:
        if e["fact"] == "what":
            e["quote"] = "he dropped the items and ran"
    sim.validator_answer = alt
    c.assess(0)
    assert summary(c)["severity"] == "HIGH"


def test_audit_rejection_blocks(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    sim.leader_answer = FULL_HIGH
    sim.audit = False
    with pytest.raises(UserError):
        c.assess(0)


def test_fabricated_quote_rejected(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    bad = json.loads(json.dumps(FULL_HIGH))
    bad["facts"][5] = {"fact": "weapon", "answer": "Y", "quote": "He pulled out a knife"}
    sim.leader_answer = bad
    with pytest.raises(Exception):
        c.assess(0)


def test_malformed_answers_rejected(env):
    sim, c, ns = env
    check = ns["_check_facts"]
    short = {"facts": FULL_HIGH["facts"][:10]}
    with pytest.raises(ValueError):
        check(short, REPORT)
    extra = json.loads(json.dumps(FULL_HIGH))
    extra["severity"] = "LOW"
    with pytest.raises(ValueError):
        check(extra, REPORT)
    n_with_quote = json.loads(json.dumps(FULL_HIGH))
    n_with_quote["facts"][5]["quote"] = "something"
    assert check(n_with_quote, REPORT)["facts"][5]["quote"] == ""  # N quotes are discarded
    maybe = json.loads(json.dumps(FULL_HIGH))
    maybe["facts"][0]["answer"] = "MAYBE"
    with pytest.raises(ValueError):
        check(maybe, REPORT)


def test_malformed_reply_is_retried_then_accepted(env):
    sim, c, _ = env
    setup_site(sim, c)
    sim.sender = OFFICER
    c.file_report(0, REPORT)
    replies = ["not json at all", FULL_HIGH]
    sim.leader_answer = lambda p: replies.pop(0) if replies else FULL_HIGH
    c.assess(0)
    assert summary(c)["severity"] == "HIGH"


def test_quote_match_ignores_spacing_and_case(env):
    sim, c, ns = env
    a = answers(who="officer:   a. khan,  ID 4471")
    out = ns["_check_facts"](a, REPORT)
    assert out["facts"][0]["answer"] == "Y"


def test_severity_rules(env):
    sim, c, ns = env
    sev = ns["_severity"]
    base = {f: "N" for f in FACTS}
    assert sev(base) == "LOW"
    assert sev(dict(base, crime_attempt="Y")) == "MEDIUM"
    assert sev(dict(base, injury="Y")) == "HIGH"
    assert sev(dict(base, weapon="Y", injury="Y")) == "CRITICAL"


# ---------- demos ----------

def test_demo_is_isolated(env):
    sim, c, _ = env
    sim.leader_answer = answers(who="Officer: S. Reid, ID 3302", what="A van tried to enter without a pass",
                                where="Eastfield Depot, gatehouse", actions="informed control")
    c.run_demo(5)
    s = json.loads(c.get_demo_summary(0))
    assert s["outcome"] == "NEEDS_AMENDMENT" and "when" in s["missing"]
    assert s["matches_expected"] is True and s["records_created"] is False
    assert json.loads(c.get_counts()) == {"sites": 0, "reports": 0, "demo_results": 1}


def test_demo_ids_validated(env):
    sim, c, _ = env
    with pytest.raises(UserError):
        c.run_demo(9)
