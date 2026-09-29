# R7 write-recheck

Batch total_ms medians; baseline fa4d51a. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. All negative reductions remain.

Independent seven fresh processes per before/current endpoint, alternating pair order; no OpenLDAP measurement or relative ratio. CRUD: 100 operations; reads/user Bind: 2; setup: 302; cleanup: 504; connect/userConnect: 1 each. Original write results remain separate.

| Access | Variant | Stage | Method | Members | Ops/batch | Before ms | Current ms | OpenLDAP ms | Relative | Time reduction |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| root | fixed-DN | connect |  | 0 | 1 | 0.28 | 0.29 | n/a | n/a | -1.0% |
| root | fixed-DN | rootBind |  | 0 | 2 | 0.37 | 0.33 | n/a | n/a | 10.4% |
| root | fixed-DN | baseSearch |  | 0 | 2 | 1.32 | 1.17 | n/a | n/a | 10.8% |
| root | fixed-DN | indexedEquality |  | 0 | 2 | 0.64 | 0.66 | n/a | n/a | -2.8% |
| root | fixed-DN | compareTrue |  | 0 | 2 | 1.12 | 1.04 | n/a | n/a | 7.0% |
| root | fixed-DN | compareFalse |  | 0 | 2 | 0.33 | 0.29 | n/a | n/a | 12.4% |
| root | fixed-DN | substringPrefix |  | 0 | 2 | 92.27 | 91.84 | n/a | n/a | 0.5% |
| root | fixed-DN | substringNegative |  | 0 | 2 | 92.37 | 92.26 | n/a | n/a | 0.1% |
| root | fixed-DN | setup |  | 0 | 302 | 981.07 | 978.25 | n/a | n/a | 0.3% |
| user | fixed-DN | userConnect |  | 0 | 1 | 0.20 | 0.20 | n/a | n/a | -1.5% |
| user | fixed-DN | userBind |  | 0 | 2 | 0.35 | 0.35 | n/a | n/a | -1.8% |
| root | fixed-DN | add |  | 0 | 100 | 91.79 | 89.79 | n/a | n/a | 2.2% |
| root | fixed-DN | modify |  | 0 | 100 | 42.38 | 43.60 | n/a | n/a | -2.9% |
| root | fixed-DN | modifyDN |  | 0 | 100 | 134.04 | 136.66 | n/a | n/a | -2.0% |
| root | fixed-DN | delete |  | 0 | 100 | 105.24 | 102.85 | n/a | n/a | 2.3% |
| root | fixed-DN | cleanup |  | 0 | 504 | 347.77 | 345.48 | n/a | n/a | 0.7% |
