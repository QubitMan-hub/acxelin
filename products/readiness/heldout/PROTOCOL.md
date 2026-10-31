# Held-out evaluation of Readiness: protocol (written before the first run)

**Why.** `products/readiness/bench/` (84 files, 179 labelled pairs) is the quality gate. Its own header says it is tuned on by construction, so its scores of 1.0 are a regression floor,
not evidence about code the detectors have never seen. This evaluation uses labels Acxelin did not write, on code Acxelin did not write, and is run so that it cannot be tuned on.

**The set.** OWASP Benchmark for Java v1.2 (OWASP-Benchmark/BenchmarkJava, GPL-2.0, so it is read from a checkout at run time and never copied into this repository). Ground truth is its own
`expectedresults-1.2.csv`. Population: every test of the categories `crypto` (CWE-327: 130 vulnerable, 116 safe) and `hash` (CWE-328: 129 vulnerable, 107 safe), 482 tests.
`weakrand` is left out: Readiness inventories algorithms, it does not judge the quality of a random number generator.

**What counts as a prediction (fixed now).** A test is predicted *positive* when Readiness reports at least one asset located in that test's file whose priority tier is
- `strict`: `critical`; or
- `broad`: `critical` or `high`.
Both rules are reported; no other rule will be added after seeing the results. The tier is the one Readiness reports (its own treatment of test code included).

**Two layouts.** (`neutral`, primary) every test is copied to `src/case_NNNNN.java`, so file and folder names cannot trigger any test-code heuristic. (`original`) the files stay under
`src/main/java/org/owasp/benchmark/testcode/BenchmarkTestNNNNN.java`. The difference between the two is itself a finding about path heuristics.

**Reported.** Per category and overall, per rule and layout: the confusion matrix, precision, recall, F1 and accuracy, each rate with a 95% Wilson score interval. Nothing else is selected after the fact.

**Rules that keep it held out.**
1. The detectors are not changed to improve these numbers. If the results expose a defect, the fix is made from a case written by hand for it (added to the tuned corpus through a `truth:` commit the owner
   approves), never from these files, and the next run of this evaluation says which detector version it measured.
2. A result file records the Readiness version and git commit, the benchmark commit, the layout and the rules. A number without that is not quoted.
3. If this set is ever used to tune anything, it stops being held out and the README of this folder says so.

**What it can show.** How Readiness's weak-algorithm findings agree with an independent label on 482 realistic-looking Java servlets.
**What it cannot show.** Anything about languages other than Java, about code that is not a servlet benchmark, about the quantum-vulnerability side of the tiers (the benchmark labels weakness, not quantum exposure),
or about live endpoints. In many of its tests the algorithm is read from a properties file at run time, which no static scan can know; those tests lower recall for every static tool and say nothing about this one in particular.
