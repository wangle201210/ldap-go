# R7 writes

Batch total_ms medians; baseline fa4d51a. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. All negative reductions remain.

Setup (62 operations), cleanup (104), connect (1), and userConnect (1) retain separate rows and actual counts. Other stages have 20 operations. Verification operations remain separately recorded in raw JSON.

| Access | Variant | Stage | Method | Members | Ops/batch | Before ms | Current ms | OpenLDAP ms | Relative | Time reduction |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| root | fixed-DN | connect |  | 0 | 1 | 0.29 | 0.30 | 0.30 | 99.9% | -4.7% |
| root | fixed-DN | rootBind |  | 0 | 20 | 3.51 | 2.53 | 2.57 | 101.4% | 28.0% |
| root | fixed-DN | baseSearch |  | 0 | 20 | 3.31 | 3.72 | 2.80 | 75.2% | -12.3% |
| root | fixed-DN | indexedEquality |  | 0 | 20 | 3.77 | 3.70 | 3.73 | 100.8% | 1.7% |
| root | fixed-DN | compareTrue |  | 0 | 20 | 3.25 | 3.20 | 2.60 | 81.1% | 1.5% |
| root | fixed-DN | compareFalse |  | 0 | 20 | 2.59 | 2.65 | 2.11 | 79.8% | -2.4% |
| root | fixed-DN | substringPrefix |  | 0 | 20 | 953.27 | 947.46 | 627.63 | 66.2% | 0.6% |
| root | fixed-DN | substringNegative |  | 0 | 20 | 961.85 | 941.08 | 630.21 | 67.0% | 2.2% |
| root | fixed-DN | setup |  | 0 | 62 | 775.89 | 774.04 | 309.91 | 40.0% | 0.2% |
| user | fixed-DN | userConnect |  | 0 | 1 | 0.21 | 0.21 | 0.22 | 102.9% | -1.9% |
| user | fixed-DN | userBind |  | 0 | 20 | 2.51 | 3.09 | 2.96 | 95.5% | -23.1% |
| root | fixed-DN | add |  | 0 | 20 | 16.96 | 23.85 | 99.91 | 418.9% | -40.6% |
| root | fixed-DN | modify |  | 0 | 20 | 8.67 | 9.75 | 88.64 | 908.9% | -12.5% |
| root | fixed-DN | modifyDN |  | 0 | 20 | 29.97 | 32.13 | 85.67 | 266.6% | -7.2% |
| root | fixed-DN | delete |  | 0 | 20 | 20.12 | 23.33 | 104.74 | 449.0% | -15.9% |
| root | fixed-DN | cleanup |  | 0 | 104 | 73.75 | 87.12 | 293.39 | 336.8% | -18.1% |
