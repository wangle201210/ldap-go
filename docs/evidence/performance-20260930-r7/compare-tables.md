# R7 Compare component

Three 1s repetitions on each side, both CPU-profiled. Profiles include expensive fixture setup; they are not query-only. Medians below come from the benchmark metrics, not profile attribution.

| Targets | Metric | Before | Current | Reduction |
| ---: | --- | ---: | ---: | ---: |
| 1 | ns/op | 21087 | 14206 | 32.6% |
| 1 | B/op | 15472 | 12272 | 20.7% |
| 1 | allocs/op | 357 | 165 | 53.8% |
| 1024 | ns/op | 24909 | 21283 | 14.6% |
| 1024 | B/op | 14566 | 12926 | 11.3% |
| 1024 | allocs/op | 464 | 325 | 30.0% |
