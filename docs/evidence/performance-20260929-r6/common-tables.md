# R6 common operations

Baseline `45c8e5d`. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. Negative reductions remain.

## explicit-final

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 110.76 ms | 108.84 ms | 87.24 ms | 80.2% | 1.7% |
| Wrong password, SSHA | Low | 1,000 | 101.23 ms | 100.78 ms | 82.03 ms | 81.4% | 0.5% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 99.56 ms | 98.77 ms | 81.20 ms | 82.2% | 0.8% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 107.89 ms | 105.25 ms | 83.31 ms | 79.2% | 2.4% |
| Non-root Base, hot | High | 1,000 | 123.53 ms | 122.60 ms | 96.82 ms | 79.0% | 0.8% |
| Non-root equality, hot | Very high | 1,000 | 126.92 ms | 125.50 ms | 96.59 ms | 77.0% | 1.1% |
| Non-root Base, distributed | High | 1,000 | 153.04 ms | 148.28 ms | 99.74 ms | 67.3% | 3.1% |
| Non-root equality, distributed | Very high | 1,000 | 129.96 ms | 128.75 ms | 93.33 ms | 72.5% | 0.9% |
| Direct group discovery | High | 100 | 20.35 ms | 19.80 ms | 14.00 ms | 70.7% | 2.7% |
| Group Base, 10 members | Medium | 100 | 13.82 ms | 13.14 ms | 10.25 ms | 78.0% | 4.9% |
| Group Base, 1,000 members | Medium | 100 | 109.53 ms | 117.74 ms | 98.70 ms | 83.8% | -7.5% |
| Nested membership, client BFS | Medium-high | 100 traversals | 56.89 ms | 53.88 ms | 42.04 ms | 78.0% | 5.3% |

## default-final

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 111.62 ms | 112.53 ms | 92.17 ms | 81.9% | -0.8% |
| Wrong password, SSHA | Low | 1,000 | 101.50 ms | 101.93 ms | 79.96 ms | 78.4% | -0.4% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 98.47 ms | 97.60 ms | 77.14 ms | 79.0% | 0.9% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 97.02 ms | 96.39 ms | 77.59 ms | 80.5% | 0.7% |
| Non-root Base, hot | High | 1,000 | 116.31 ms | 116.65 ms | 94.02 ms | 80.6% | -0.3% |
| Non-root equality, hot | Very high | 1,000 | 120.76 ms | 121.35 ms | 94.36 ms | 77.8% | -0.5% |
| Non-root Base, distributed | High | 1,000 | 134.16 ms | 143.99 ms | 97.43 ms | 67.7% | -7.3% |
| Non-root equality, distributed | Very high | 1,000 | 151.36 ms | 168.85 ms | 110.86 ms | 65.7% | -11.6% |
| Direct group discovery | High | 100 | 20.24 ms | 18.93 ms | 16.05 ms | 84.8% | 6.4% |
| Group Base, 10 members | Medium | 100 | 17.61 ms | 16.02 ms | 12.56 ms | 78.4% | 9.0% |
| Group Base, 1,000 members | Medium | 100 | 105.10 ms | 108.42 ms | 100.62 ms | 92.8% | -3.2% |
| Nested membership, client BFS | Medium-high | 100 traversals | 57.55 ms | 57.20 ms | 44.32 ms | 77.5% | 0.6% |
