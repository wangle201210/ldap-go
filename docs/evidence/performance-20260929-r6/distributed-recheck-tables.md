# R6 independent default-access distributed recheck

Seven repeats of 1,000 calls per endpoint, before the default 1,000-member group recheck.
Fresh processes and initial seeds; original three-repeat Base/equality rows remain unchanged.
No pooling with or substitution for the original common samples.

| Workload | Calls | Repeats | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Non-root Base, distributed | 1,000 | 7 | 132.39 ms | 129.22 ms | 96.36 ms | 74.6% | 2.4% |
| Non-root equality, distributed | 1,000 | 7 | 134.31 ms | 133.91 ms | 100.76 ms | 75.2% | 0.3% |
