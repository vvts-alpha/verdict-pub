# Benchmark tooling

Run these scripts from the root of `verdict-pub` with Node.js 24 or later. Reports and charts are written under `benchmarks/`. The source code and private assessment databases stay in separate local directories.

The report generators need a built [VERDICT source checkout](https://github.com/vvts-alpha/VERDICT). In that checkout, run `pnpm install --frozen-lockfile` and `pnpm --filter @veritas/core build`. The static UI exporter also requires `pnpm -r build` to build the WebUI bundle.

```bash
# Run from verdict-pub; use paths for your local checkouts and private data.
export VERDICT_SOURCE_DIR="../VERDICT"
export VERDICT_RUNS_DIR="../VERDICT/runs"
node scripts/bench-score.mjs --map scripts/bench-map.tsv
node scripts/build-xbow-bench.mjs
node scripts/build-juice-shop.mjs
```

`bench-score.mjs` reads SQLite databases without modifying them and does not need the source checkout. The generators use the run IDs and dates recorded in the benchmark CSV or script. Missing private inputs cannot be recreated from the public reports.

```bash
node scripts/export-static-ui.mjs <assessment-id> "$VERDICT_RUNS_DIR" /tmp/verdict-sample-ui.html
```

Generated reports and UI exports can include raw requests, responses, account data, and screenshots. Redact private data before publication. Keep the existing anonymization in public reports; never commit run directories, session stores, credentials, or browser profiles.
