# Contributing

Bug reports, questions and pull requests are all welcome.

## The one hard rule

**No runtime dependencies.**

LogSentry is meant to run on a host you have just started to distrust, where
installing software is neither safe nor practical. If a change requires
anything that is not already on a stock Linux, macOS or BSD install, it does
not belong in `bin/` or `lib/`.

Development tooling is a different matter — `shellcheck` and the Python script
that regenerates the documentation screenshots are fine, because neither is
needed to *run* the tool.

## Getting set up

```bash
git clone https://github.com/Dc0der-X/Log-File-Integrity-Monitor.git
cd Log-File-Integrity-Monitor
make test          # 73 assertions, no framework to install
make syntax        # parse every script
make lint          # shellcheck, if you have it
./demo/demo.sh     # see it work
```

## Before opening a pull request

```bash
make check-all     # syntax + tests
make lint
```

CI runs the suite on Ubuntu **and** macOS. That matters more here than in most
projects: GNU coreutils and BSD userland disagree on `stat` flags, on whether
`md5sum` exists, and on `date` arithmetic. A change that works on your laptop
may not work on the other half of the matrix.

## Shell style

The existing code is the style guide, but in short:

- **bash 3.2 compatible.** macOS still ships 3.2, so no associative arrays, no
  `${var^^}`, no `readarray`.
- **Quote every expansion** unless you specifically want globbing or splitting,
  and add a `# shellcheck disable=` with a reason where you do.
- **Never `eval`, and never `source` untrusted input.** The config parser
  assigns with `printf -v` for this reason; there is a regression test.
- **Prefix internal functions with `ls_`** to keep the sourced namespace clean.
- **Diagnostics to stderr, data to stdout,** so `--format json | jq` keeps
  working.
- **Portability shims go in `lib/common.sh`,** resolved once at start-up.
  Do not scatter `if [ "$(uname)" = Darwin ]` through the codebase.

## Tests

Every behavioural change needs a test. The harness is `tests/run_tests.sh` —
add a function named `test_*` and it is picked up automatically:

```bash
test_my_new_behaviour() {
  setup; seed_logs; baseline
  # …do something to the files…
  check
  assert_contains "EXPECTED_VERDICT"
  assert_rc 2
}
```

Available helpers: `setup`, `seed_logs`, `baseline`, `check`, `sentry`,
`assert_contains`, `assert_not_contains`, `assert_rc`, `assert_true`.

Run a subset while iterating:

```bash
./tests/run_tests.sh rotation
```

Each test gets its own scratch and state directory, so tests cannot see each
other's baselines.

## Changes to detection logic

This is the part of the codebase where a subtle mistake is a security bug, so
detection changes get extra scrutiny. Please include:

1. **The scenario**, concretely: what an attacker or a daemon does to the file.
2. **A test that fails before your change and passes after.**
3. **A note on false positives.** Anything that fires on routine activity gets
   the whole tool muted — that failure mode is discussed in
   [docs/DETECTION-LOGIC.md](docs/DETECTION-LOGIC.md#1-why-comparing-digests-is-not-enough).
4. **An update to the decision table** in that document if you add or reorder
   a rule.

## Documentation

The four documents under `docs/` are part of the project, not an afterthought.
If you change behaviour, update the document that describes it — the decision
table in `DETECTION-LOGIC.md`, the threat model in `ARCHITECTURE.md`, and the
flag reference in `USAGE.md` are all meant to be accurate.

Screenshots in `docs/images/` are generated from real program output:

```bash
FORCE_COLOR=1 ./demo/demo.sh --fast > /tmp/demo.ansi
python3 tools/ansi2html.py /tmp/demo.ansi "title" "logsentry" > /tmp/demo.html
# then screenshot /tmp/demo.html at 1300px wide
```

Please do not hand-edit them — a screenshot that no longer matches what the
tool prints is a documentation bug.

## Reporting a security issue

If you find a way to defeat the detection logic, or a privilege-escalation path
in the tool itself, please open an issue describing the scenario. Given the
nature of the project, a proof-of-concept that survives `make test` is the most
useful thing you can attach.
