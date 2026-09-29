# R6 paired root operations

Baseline `45c8e5d`; seven batches per variant. Literal and uppercase client DNs stay separate.
Root Base uses a fixed container; equality and Compare use distributed UIDs.
Untimed WhoAmI and fixture work prevent pooling with the historical R4 serial probe.

## literal: `cn=admin,dc=scale,dc=qualification`

| Stage | Method | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rootBind | simple_bind_root | 1,000 | 77.42 ms | 78.38 ms | 75.33 ms | 96.1% | -1.2% |
| rootBase | base_objectclass_root | 1,000 | 113.60 ms | 110.54 ms | 92.30 ms | 83.5% | 2.7% |
| rootEquality | subtree_uid_equality_root | 1,000 | 150.01 ms | 150.95 ms | 119.99 ms | 79.5% | -0.6% |
| rootCompareTrue | compare_uid_true_root | 1,000 | 121.15 ms | 122.15 ms | 80.39 ms | 65.8% | -0.8% |
| rootCompareFalse | compare_uid_false_root | 1,000 | 114.02 ms | 113.51 ms | 77.59 ms | 68.4% | 0.4% |

## normalized: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`

| Stage | Method | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rootBind | simple_bind_root | 1,000 | 77.02 ms | 77.94 ms | 74.37 ms | 95.4% | -1.2% |
| rootBase | base_objectclass_root | 1,000 | 109.30 ms | 111.01 ms | 87.86 ms | 79.1% | -1.6% |
| rootEquality | subtree_uid_equality_root | 1,000 | 116.10 ms | 117.19 ms | 92.54 ms | 79.0% | -0.9% |
| rootCompareTrue | compare_uid_true_root | 1,000 | 125.97 ms | 126.94 ms | 83.35 ms | 65.7% | -0.8% |
| rootCompareFalse | compare_uid_false_root | 1,000 | 136.50 ms | 137.60 ms | 83.21 ms | 60.5% | -0.8% |
