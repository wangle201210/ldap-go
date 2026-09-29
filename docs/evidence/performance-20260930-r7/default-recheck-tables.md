# R7 default-recheck

Batch total_ms medians; baseline fa4d51a. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. All negative reductions remain.

| Access | Variant | Stage | Method | Members | Ops/batch | Before ms | Current ms | OpenLDAP ms | Relative | Time reduction |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default | distributed | nonrootBase | search_nonrootBase | 0 | 1000 | 130.72 | 131.32 | 98.02 | 74.6% | -0.5% |
| default | distributed | nonrootEquality | search_nonrootEquality | 0 | 1000 | 133.85 | 131.94 | 99.36 | 75.3% | 1.4% |
| default | hot | userBind | simple_bind_ssha | 0 | 1000 | 99.63 | 98.29 | 78.18 | 79.5% | 1.3% |
| default | hot | userBind | simple_bind_plaintext | 0 | 1000 | 97.62 | 97.38 | 79.12 | 81.2% | 0.2% |
