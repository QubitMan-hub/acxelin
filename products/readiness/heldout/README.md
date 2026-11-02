# Held-out evaluation of Readiness

Protocol: [PROTOCOL.md](PROTOCOL.md), written and committed before the first run on the real set. Result file: `results/owasp-1.2-readiness-1.1.1.json` (Readiness 1.1.1, OWASP Benchmark for Java v1.2 at
commit `f40c618c5a709afce350ef06ed2899c85cf586e9`). Rerun: check out BenchmarkJava, then
`python -m acxelin_readiness.heldout --benchmark PATH --out results/owasp-1.2-readiness-<version>.json`. The set is GPL-2.0 and is not copied here.

This was run **once** on this detector version. No detector was changed because of it.

## Result (registered rates, 482 tests: 246 `crypto`, 236 `hash`; 95% Wilson intervals)

Neutral file names (primary). The `strict` rule (critical only) and the `broad` rule (critical or high) give identical counts: Readiness never reports "high" for these tests.

| | tp | fp | fn | tn | precision | recall | accuracy |
|---|---|---|---|---|---|---|---|
| overall | 219 | 27 | 40 | 196 | 0.890 [0.845, 0.923] | 0.846 [0.797, 0.884] | 0.861 [0.827, 0.889] |
| `crypto` (246) | 130 | 27 | 0 | 89 | 0.828 [0.761, 0.879] | 1.000 [0.971, 1.000] | 0.890 [0.845, 0.923] |
| `hash` (236) | 89 | 0 | 40 | 107 | 1.000 [0.959, 1.000] | 0.690 [0.606, 0.763] | 0.831 [0.777, 0.873] |

Original file names (the files left under `.../testcode/BenchmarkTestNNNNN.java`): the `broad` rule gives the same table; the `strict` rule gives tp = 0, because every critical finding is reported one tier lower.

## What the numbers mean, and do not mean

- **After the fact, descriptive, not a registered rate:** the 349 tests that name the algorithm in the code have 0 errors (349/349, 95% interval [0.989, 1.000]); all 67 errors are among the 133 tests that
  read the algorithm name from `benchmark.properties` (66/133 right, [0.413, 0.580]). My split is a text match on `getProperty` and `benchmark.properties`; it is in `heldout.algorithm_source`.
  Only the test sources were scanned: the properties file was not part of the scanned folder, so a scan of the whole checkout might do better. That is a different evaluation, to be registered and labelled as one,
  not run here to improve this one.
- **Do not quote 0.846 as "Readiness's recall".** It is its recall on this synthetic Java servlet benchmark, for weakness labels, with 28% of the tests unknowable to a one-file static scan.
- **Since changed:** only folders named test, tests, __tests__ and spec now count as test code by themselves (the owner's decision; customers add others with `test_paths`). The result below was recorded under the old rule and is kept as it was.
- **The test-code rule demotes these files.** With the original names every critical finding is reported as `high`. That is `rank.py` lowering a test-only finding by one tier (`test_only` assets) because
  `is_test` treats the directory `testcode` as test code (I did not isolate which clause of `is_test` matched). For a repository whose production code lives under a folder with "test" in its name this would hide
  critical findings from the priority list; whether that needs a change is the owner's decision, and any change must be driven by a hand-written case, not by these files.
- The benchmark labels *weakness*. Readiness's tiers also express quantum exposure, which this set cannot assess.
- Java only. Nothing here says anything about Python, Go, JavaScript, C, certificates, keystores or live endpoints.

## Next evaluation sets, not done

Held-out sets for Python and for live-endpoint grading need independent labels that I could not find ready-made; building them means labelling by someone other than the person who writes the detectors.
