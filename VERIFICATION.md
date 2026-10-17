# Security Incident Log verification

Contract file: `contract.py`, version `incident-log-0.2`.

## Local checks completed

- Python syntax compilation succeeded.
- Every GenLayer SDK call the contract uses (`gl.vm.run_nondet_unsafe`, `gl.vm.Return`, `gl.nondet.exec_prompt`, `gl.vm.UserError`, `gl.message.sender_address`) is the same set used by my Deposit Dispute Court contract, which ran end to end on GenLayer Studio with the same `py-genlayer` runner.
- `test_contract.py`: **20 tests passed** against a simulated GenLayer runtime.

The official `genlayer-test` package couldn't be installed in the environment used, so the tests use a small simulated runtime instead. All AI answers in the tests are authored fixtures. They check the contract's deterministic behaviour, not the AI's judgement.

## What the tests cover

1. Full lifecycle for a HIGH incident: assessment, escalation note required, hash sign-off, officer and site records.
2. Incomplete report sent back with the exact missing facts, amended (new hash), re-assessed and closed.
3. One review per report, with the reason passed to the validators.
4. Officer and supervisor must be different addresses; only the supervisor adds officers; only site officers file.
5. Only the supervisor can sign off, and only with the exact `report_hash`.
6. Only the filing officer can amend; the amendment limit is enforced.
7. A report can't be assessed twice without a new version or review.
8. A validator reaching a different outcome blocks the assessment and leaves the report unchanged.
9. Validators quoting different words but reaching the same outcome still agree.
10. A failed audit blocks the assessment.
11. Fabricated quotes, missing or extra facts, extra fields and unknown answers are rejected; quotes on N answers are discarded.
12. A malformed AI reply is asked again (up to 3 attempts) instead of failing the transaction.
13. Quote matching tolerates spacing and capital letters only.
14. Severity rules.
15. Demos are isolated: no sites, reports or officer records are created.

## Live Studio evidence

Recorded in GenLayer Studio on 17 October 2026 at `0x56B09345876fa22b7e9b16E20c21F44c5dA17C7E`. Full details and screenshots are in [DEMO_RESULTS.md](DEMO_RESULTS.md).

- All 5 isolated demos matched their expected outcome, including the prompt-injection case, and created no records.
- A real two-account report ran end to end: vague report sent back (who, when, where, actions missing) → amended (new hash) → re-assessed HIGH with escalation → supervisor signed off the exact hash with a note → CLOSED.
- Site stats and officer record updated by code: filed 1, sent back 1, closed 1, HIGH 1.
