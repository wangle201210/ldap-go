# R16 Profiling Diagnostics

Text logs only; all profiling measurements are excluded from timing and allocation comparison tables. No binary profile was read, hashed or archived.

The initial unanchored members-10 pattern also selected members-1000. Its log is eligible-profile-both.txt; the associated binary name small-eligible.cpu.pprof does not imply a small-only profile. The corrected anchored ^members-10$ run appears in small-eligible-profile.txt and selected only the 10-member eligible case. Its binary was named small-eligible-only.cpu.pprof.

These are exploratory profile runs, not unprofiled before/current measurements or proof of retained-heap improvement. R16 is REJECTED / NOT SHIPPED: small-group overhead remained unresolved.
