# Path changes from the cleanup

No file was moved. Evidence, tests, `.zap/` and docs keep their paths so existing report citations stay valid.

## Removed

| Old path | Notes for the report |
|---|---|
| `docs/HANDOFF_Security_Gap_Plan.md` | Finished agent handoff. Not cited by the report. |
| `docs/Kura_Security_Gap_Plan.md` | Agent task plan. Not cited by the report. |
| `docs/SECURITY_TRIVY_FINDINGS.md` | **Cited 5 times in the FULL report.** Update those citations; scan results live in `docs/evidence/` and `docs/coursework/TEST_RESULTS_SUMMARY.md`. Still available in git history (`git show 06fc1a0:docs/SECURITY_TRIVY_FINDINGS.md`). |
| `docs/coursework/reference/standards/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv` | **Cited once in the FULL report.** Update the citation or restore it from history (`git show 06fc1a0:...`). |
| `docs/coursework/reference/standards/OWASP_SCP_Quick_Reference_Guide.en-US.pdf` | Reference material, not used by the code. |

## Edited in place

| Path | Change |
|---|---|
| `.github/workflows/security.yml` | `security-tests` push trigger removed; comment no longer points at the deleted Trivy doc. |
| `.zap/rules.tsv` | Header says the file is used by `scripts/zap-baseline.sh`, not CI. |
| `docs/coursework/TEST_RESULTS_SUMMARY.md` | T3 says ZAP runs locally, not in CI. |
| `docs/coursework/LECTURE_TRACEABILITY.md` | No longer points at the deleted gap plan. |
| `docs/evidence/security-tests/TEST_LOG.md` | ST-19, ST-20, ST-28, ST-43 and ST-07 note that the CI ZAP job and the Trivy doc were removed. |
| `docker/postgres/restore.sh`, `kura/*.py` | Comment and banner cleanup only. |

## Synced from the parallel thread (unchanged content)

`architecture.py`, `docs/Kura Secure Learning Management System/Kura Secure Learning Management System 4259050eb027828cb06d81fdb7397e7a.md` and `docs/Kura Secure Learning Management System/kuras_secure_architecture.png`.
