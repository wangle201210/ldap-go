# R7 common

Batch total_ms medians; baseline fa4d51a. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. All negative reductions remain.

| Access | Variant | Stage | Method | Members | Ops/batch | Before ms | Current ms | OpenLDAP ms | Relative | Time reduction |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default | distributed | nonrootBase | search_nonrootBase | 0 | 1000 | 142.88 | 142.90 | 101.18 | 70.8% | -0.0% |
| default | distributed | nonrootEquality | search_nonrootEquality | 0 | 1000 | 144.17 | 156.22 | 109.66 | 70.2% | -8.4% |
| default | groups | memberEquality | search_memberEquality | 0 | 100 | 16.45 | 16.56 | 12.34 | 74.5% | -0.6% |
| default | groups | groupBase | base_member_values | 10 | 100 | 26.14 | 18.89 | 17.97 | 95.1% | 27.7% |
| default | groups | groupBase | base_member_values | 1000 | 100 | 109.23 | 105.72 | 96.22 | 91.0% | 3.2% |
| default | groups | nestedMembership | client_bfs_member_equality | 0 | 100 | 48.73 | 50.05 | 39.97 | 79.9% | -2.7% |
| default | hot | userBind | simple_bind_ssha | 0 | 1000 | 139.73 | 149.18 | 119.84 | 80.3% | -6.8% |
| default | hot | userBind | simple_bind_plaintext | 0 | 1000 | 125.93 | 126.29 | 102.75 | 81.4% | -0.3% |
| default | hot | userBindWrong | simple_bind_ssha | 0 | 1000 | 113.90 | 108.10 | 94.46 | 87.4% | 5.1% |
| default | hot | userBindWrong | simple_bind_plaintext | 0 | 1000 | 114.77 | 111.43 | 93.97 | 84.3% | 2.9% |
| default | hot | nonrootBase | search_nonrootBase | 0 | 1000 | 126.88 | 124.55 | 101.22 | 81.3% | 1.8% |
| default | hot | nonrootEquality | search_nonrootEquality | 0 | 1000 | 128.96 | 129.56 | 102.93 | 79.4% | -0.5% |
| explicit | distributed | nonrootBase | search_nonrootBase | 0 | 1000 | 142.11 | 141.74 | 103.05 | 72.7% | 0.3% |
| explicit | distributed | nonrootEquality | search_nonrootEquality | 0 | 1000 | 145.10 | 148.00 | 106.70 | 72.1% | -2.0% |
| explicit | groups | memberEquality | search_memberEquality | 0 | 100 | 16.72 | 15.12 | 11.70 | 77.4% | 9.5% |
| explicit | groups | groupBase | base_member_values | 10 | 100 | 13.37 | 12.95 | 10.11 | 78.1% | 3.1% |
| explicit | groups | groupBase | base_member_values | 1000 | 100 | 106.30 | 106.72 | 95.67 | 89.6% | -0.4% |
| explicit | groups | nestedMembership | client_bfs_member_equality | 0 | 100 | 53.98 | 53.45 | 42.69 | 79.9% | 1.0% |
| explicit | hot | userBind | simple_bind_ssha | 0 | 1000 | 114.88 | 111.54 | 90.41 | 81.1% | 2.9% |
| explicit | hot | userBind | simple_bind_plaintext | 0 | 1000 | 102.00 | 99.40 | 80.26 | 80.7% | 2.5% |
| explicit | hot | userBindWrong | simple_bind_ssha | 0 | 1000 | 103.12 | 102.20 | 79.11 | 77.4% | 0.9% |
| explicit | hot | userBindWrong | simple_bind_plaintext | 0 | 1000 | 108.06 | 104.47 | 89.05 | 85.2% | 3.3% |
| explicit | hot | nonrootBase | search_nonrootBase | 0 | 1000 | 141.98 | 133.99 | 107.48 | 80.2% | 5.6% |
| explicit | hot | nonrootEquality | search_nonrootEquality | 0 | 1000 | 143.70 | 135.40 | 108.61 | 80.2% | 5.8% |
