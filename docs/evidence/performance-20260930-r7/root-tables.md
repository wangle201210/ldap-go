# R7 root

Batch total_ms medians; baseline fa4d51a. Relative = OpenLDAP/current * 100%; time reduction = (1-current/before) * 100%. All negative reductions remain.

| Access | Variant | Stage | Method | Members | Ops/batch | Before ms | Current ms | OpenLDAP ms | Relative | Time reduction |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| root | literal | rootBind | simple_bind_root | 0 | 1000 | 79.09 | 79.42 | 79.27 | 99.8% | -0.4% |
| root | literal | rootBase | base_objectclass_root | 0 | 1000 | 119.66 | 115.24 | 91.21 | 79.2% | 3.7% |
| root | literal | rootEquality | subtree_uid_equality_root | 0 | 1000 | 141.05 | 139.66 | 120.08 | 86.0% | 1.0% |
| root | literal | rootCompareTrue | compare_uid_true_root | 0 | 1000 | 126.29 | 121.11 | 85.64 | 70.7% | 4.1% |
| root | literal | rootCompareFalse | compare_uid_false_root | 0 | 1000 | 119.84 | 117.14 | 81.19 | 69.3% | 2.3% |
| root | normalized | rootBind | simple_bind_root | 0 | 1000 | 77.19 | 79.26 | 78.13 | 98.6% | -2.7% |
| root | normalized | rootBase | base_objectclass_root | 0 | 1000 | 121.70 | 119.58 | 95.67 | 80.0% | 1.7% |
| root | normalized | rootEquality | subtree_uid_equality_root | 0 | 1000 | 119.97 | 120.47 | 95.92 | 79.6% | -0.4% |
| root | normalized | rootCompareTrue | compare_uid_true_root | 0 | 1000 | 130.10 | 126.96 | 86.39 | 68.0% | 2.4% |
| root | normalized | rootCompareFalse | compare_uid_false_root | 0 | 1000 | 129.17 | 120.84 | 83.82 | 69.4% | 6.4% |
