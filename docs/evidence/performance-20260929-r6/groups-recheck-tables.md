# R6 independent 1,000-member group recheck

Seven repeats of 100 calls per endpoint, after the original common and root runs.
Fresh processes and the same initial seeds; this table contains only groupBase with 1,000 members.
The default session first ran the separately reported distributed Base/equality recheck.
The original three-repeat group regressions remain in common-tables.md.
These samples are neither pooled with nor substituted for the original runs.

| Access | Calls | Repeats | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| explicit-groups-recheck | 100 | 7 | 102.18 ms | 101.56 ms | 93.85 ms | 92.4% | 0.6% |
| default-groups-recheck | 100 | 7 | 102.26 ms | 104.20 ms | 92.91 ms | 89.2% | -1.9% |
