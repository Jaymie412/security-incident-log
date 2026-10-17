# Security Incident Log

A GenLayer Intelligent Contract that answers: **is this security incident report complete enough to file, and how serious is it?**

A site supervisor adds officers. An officer files an incident report. GenLayer validators each check the report against a fixed set of fact questions, quote the report word for word for every fact they find, and must independently reach the same outcome. Code then decides whether the report is sent back for amendment or goes to the supervisor, how severe the incident is, and whether escalation is required. The supervisor signs off the exact report version by its hash.

Example: a report that says "earlier tonight" with no date, time, place or officer ID is sent back with `missing: ["who","when","where","actions"]`. A complete report where a man produced a knife is **CRITICAL** and cannot be signed off without a supervisor note.

## Why I built it

I've worked in security for several years, in Nigeria and now the UK. Incident reports are often missing the basics: who wrote it, exactly when and where it happened, and what was done about it. Weak reports cause problems later with clients, insurers and the police. This contract checks every report against the same published definitions, explains what is missing with quotes, and keeps a tamper-evident record of what the supervisor signed off.

## What is implemented

- **Two distinct parties.** The supervisor and officer must be different addresses. Only officers added to a site can file reports there.
- **Sign-off bound to the exact report.** Every report version gets a fingerprint (`report_hash`). The supervisor must sign off with that exact hash, so they approve the version that was checked, not a later edit.
- **Verified quotes.** For every fact answered Y, the AI must quote the report word for word, and the contract checks the quote really appears in the report. Made-up quotes are rejected.
- **Independent agreement.** Using `gl.vm.run_nondet_unsafe`, each validator answers every fact question itself and must reach the same outcome as the leader (the same missing facts, or the same severity). It then audits the leader's answers and quotes and rejects them if they are wrong or misleading.
- **Code decides the outcome.** The AI only answers Y/N questions. Missing facts, completeness score, severity, escalation, status and officer records are calculated by fixed rules.
- **No state changes until the assessment passes every check.**
- **Amendments.** A report missing facts goes back to the officer, up to 3 times. Every version is kept.
- **One review per report** by the officer or supervisor, with a reason, then re-assessment.
- **Escalation rule.** HIGH and CRITICAL incidents need a supervisor note of at least 20 characters to be signed off.
- **Officer and site records:** reports closed, sent back, complete first time, and closed incidents by severity.
- **Five isolated fictional demos**, including a prompt-injection case. Demos never create sites, reports or records.

## Lifecycle

| Step | Who | Method | Status after |
|---|---|---|---|
| Create site | Supervisor | `register_site(site_name)` | |
| Add officer | Supervisor | `add_officer(site_id, officer_address)` | |
| File report | Officer | `file_report(site_id, report_text)` | SUBMITTED |
| Check report | Anyone | `assess(report_id)` | NEEDS_AMENDMENT or AWAITING_SIGN_OFF |
| Fix report (max 3) | Officer | `amend_report(report_id, new_text)` → `assess` | SUBMITTED → ... |
| Sign off | Supervisor | `sign_off(report_id, expected_report_hash, supervisor_note)` | CLOSED |
| Or review once | Officer or supervisor | `request_review(report_id, reason)` → `assess` | UNDER_REVIEW → ... |

Read methods: `get_site`, `get_report`, `get_report_summary` (shows `report_hash`), `get_counts`, `get_officer_record`, `get_policy`, `get_demo`, `get_demo_result`, `get_demo_summary`. Demo write: `run_demo(case_id)`.

## Rules (summary)

Required facts (each worth 20 points): **who** (officer name or ID), **what**, **when** (date and time), **where** (a named site or location), **actions** (a follow-up action, not just challenging someone). Any missing fact sends the report back.

Severity, from the agreed answers:

| Severity | Rule |
|---|---|
| CRITICAL | weapon or threat to life |
| HIGH | injury, police involved, or loss or damage |
| MEDIUM | attempted crime |
| LOW | none of the above |

HIGH and CRITICAL require escalation. The full definitions are returned by `get_policy`.

## Quick start in Studio

1. Import `contract.py` into GenLayer Studio and deploy with no arguments.
2. Call `run_demo` with `case_id = 1` and wait for it to be accepted.
3. Call `get_demo_summary` with `result_id = 0`. Expected: outcome `COMPLETE`, severity `LOW`, `matches_expected: true`, `records_created: false`.

See [DEMO_GUIDE.md](DEMO_GUIDE.md) for all five demos and the full two-account walkthrough.

## Demonstrated in Studio

See [DEMO_RESULTS.md](DEMO_RESULTS.md) for the recorded run, deployment address and screenshots.

## Testing

`test_contract.py` contains 20 local tests using a simulated GenLayer runtime and authored AI answers. They check roles, the lifecycle, hash sign-off, amendments, review, quote checking, validator disagreement, audit rejection, malformed AI output and retries, severity rules and demo isolation. They test the contract's behaviour, not the AI's judgement. See [VERIFICATION.md](VERIFICATION.md).

## Boundaries

- This is a checked record of an incident report, not a police report or a legal finding.
- The contract checks what the report says, not whether it is true.
- All data is public on-chain. Use fictional or anonymised reports; never real names of members of the public.
- Instructions hidden in a report are treated as data. This reduces prompt injection but doesn't guarantee against it.
- Strict independent agreement means a genuinely borderline report may fail to reach consensus and need retrying, or a clearer report.
- Different addresses do not prove different people.

## Built with

- [GenLayer](https://docs.genlayer.com) Intelligent Contracts (Python, GenVM v0.2.16 runner)
- Developed with help from Claude
