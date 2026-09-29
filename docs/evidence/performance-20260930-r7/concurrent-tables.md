# R7 concurrent

Batch total_ms medians; baseline fa4d51a. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. All negative reductions remain.

| Access | Variant | Stage | Method | Members | Ops/batch | Before ms | Current ms | OpenLDAP ms | Relative | Time reduction |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| explicit | 8-workers | uidEquality | ldapsearch | 0 | 8000 | 452.00 | 382.00 | 358.00 | 93.7% | 15.5% |
| default | 8-workers | uidEquality | ldapsearch | 0 | 8000 | 355.00 | 398.00 | 486.00 | 122.1% | -12.1% |
