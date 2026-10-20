# Risk engine

`backend/app/risk.py` implements a deterministic, explainable baseline: 15 points per recent failed attempt, +20 for a throttle signal and +10 for unfamiliar client characteristics; score is bounded 0–100, with severity bands LOW 0–29, MEDIUM 30–59, HIGH 60–79, CRITICAL 80–100. Decision labels: ALLOW, MONITOR, STEP_UP_AUTH, BLOCK. Missing metadata adds no score. Unit tests cover bounds, mapping and explanations.

The login route currently applies a simple recent-source failure counter and persists score/severity/decision. Critical-risk sign-in is denied; high risk without MFA fails closed, while MFA-enabled accounts proceed only to the MFA challenge. Repeated-failure alerts are persisted and open-alert deduplication is applied. This is a heuristic, not trained AI, calibrated risk scoring or a validated threat model. No geographic/IP reputation source exists.
