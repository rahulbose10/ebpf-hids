# Detection Engine — Rule Layer Measurement

## Command used

python tests/measure_rules.py

## Method
A replay corpus was built where each of the 14 rules has one malicious case and one
benign case. Ground truth (which pid is malicious vs benign) was fixed at corpus
construction time, using dedicated pid ranges (malicious: 1000s, benign: 2000s) —
NOT by asking the rules themselves. This avoids circular measurement: the rules
are being judged against an independently-known answer, not their own output.

## Before (Phase 1 only, 4 rules)
4 rules / 4 techniques (T1071, T1059, T1055, T1548)

## After (Phase 1 + Phase 2, all 14 rules)

Actual output from running python tests/measure_rules.py:

Total events: 54
Total alerts: 14
Rules loaded: 14

True Positives (malicious pid, alerted):  14 / 14
False Negatives (malicious pid, missed):  0
False Positives (benign pid, alerted):    0
True Negatives (benign pid, silent):      14 / 14

Precision: 1.000
Recall:    1.000
F1:        1.000

Techniques covered (9): T1003, T1055, T1059, T1070, T1071, T1222, T1486, T1547, T1548

## Test suite
python -m pytest tests/ -q
38 passed (4 in test_features.py, 14 in test_dsl_engine.py, 20 in test_dsl_rules.py -
10 Phase 2 rules x positive+negative)

## Interpretation
Perfect scores here reflect a clean, deliberately-separated corpus (each rule tested
in isolation with clearly malicious vs clearly benign inputs), not a claim that the
engine would score 1.000 against real, noisy, adversarial traffic. A real-world
deployment would need a larger, messier corpus with edge cases and borderline
behavior to get a meaningful precision/recall estimate.

## Resolved gaps (previously noted, now fixed)
- Rule file organization now matches spec: 00_core.yml has exactly the 4 core rules,
  10_filesystem.yml has ransomware_burst plus the 5 filesystem rules (6 total). The
  earlier bonus rule (mass_file_write_ransomware) was removed since it wasn't in the
  spec and had no dedicated test, to keep the rule count exactly at the spec's 14.
- Added tests/test_dsl_rules.py with a dedicated positive+negative pytest for all 10
  Phase 2 rules, closing the gap found by an external review of the actual repo.