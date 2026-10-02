# Contributing to Formwork

Thanks for your interest. This file is the practical how-to; the *why* and the project's rules of
construction live in [`constitution.md`](constitution.md), which governs the codebase. Read it before
a substantial change — it is short and it is binding.

## Getting set up

Formwork is a Rust workspace (MSRV **1.85**) with a `uv`-managed Python test harness.

```sh
cargo build --workspace          # or: just build
just check                       # the local gate: fmt + clippy (-D warnings) + tests, all --locked
```

`just check` mirrors CI's lint and test jobs. The Python black-box harness, the Linux enforcement
suite, and the networked MCP integration test are separate:

```sh
cd py && uv run pytest -q        # or: just test-e2e — drives the built CLI as an embedder would
just test-linux                  # Linux enforcement in Docker (Docker's own sandbox disabled)
just test-integration-mcp        # gateway shading against a real published MCP server (needs npx)
```

Platform-backend tests skip-with-reason off their platform (macOS Seatbelt vs. Linux
Landlock/seccomp). A skip still reports `ok` under `cargo test`, so CI sets
`FW_REQUIRE_EXERCISED=1`, which turns a test that cannot exercise its mechanism into a failure; set
it locally to check that your machine ran what you think it ran. Run what your machine can enforce
and let CI cover the rest. Docker's own seccomp profile and AppArmor are disabled for the Linux
container (`just test-linux`) because the default seccomp profile allowlisted the `landlock_*`
syscalls only recently and AppArmor can shadow a Landlock denial with its own.

`main` is verified once more, on every push and nightly, by `.github/workflows/e2e-verify.yml`:
the whole suite, the networked MCP test and the latency budgets on every release platform (Linux
and macOS, x86_64 and arm64), decided by `py/e2e_matrix.py` against `formwork.md`. A §7 test that
is not on §10's not-yet-implemented list must pass on each OS its title names, and a test that
skipped at runtime counts as not run. The run summary carries the test × platform matrix. To
reproduce one column locally, put `formwork explain --json` (as `host.json`), `cargo test
--workspace -- --show-output` (as `cargo-test.log`) and the harness run with
`FW_E2E_RESULTS=<dir>/pytest.json` in one directory under `results/`, then run
`python3 py/e2e_matrix.py --results results`.

## Making a change

1. Branch from `main`.
2. Keep the change focused. Behavioral changes and large mechanical refactors belong in separate PRs
   so each stays reviewable.
3. Match the surrounding code — the constitution's *Comments* (why-only) and *Vocabulary* (one word
   per concept) sections are enforced in review.
4. Requirement identifiers (`FW-*`) are stable and minted once (constitution: *Requirements &
   identifiers*). Cite them in code and tests; link them in markdown. `test_requirements.py` is the
   canary — every cited ID must resolve to exactly one anchored definition in `formwork.md` (or
   `docs/fep-1.md`), and every markdown requirement link must land. It runs on any host.
5. `just check` must be green, and the Python harness green for anything it covers, before you open
   a PR.

## Where things live

- [`formwork.md`](formwork.md) — the design and end-to-end test spec; the FW-* definitions, and
  the build order (§12).
- [`constitution.md`](constitution.md) — doctrine, including the crate layers and what each crate
  may depend on (*Layers*).
- [`docs/STATUS.md`](docs/STATUS.md) — implementation status by phase, and the work still owed.
- [`docs/`](docs/) — enhancement proposals (`fep-*.md`), their execution records (`fep-*-plan.md`),
  and supporting design notes ([`linux-backend.md`](docs/linux-backend.md),
  [`macos-characterization.md`](docs/macos-characterization.md)).
- [`examples/`](examples/README.md) — blueprints and agent wiring, checked by the harness.

## Security

Please do not open public issues for vulnerabilities — see [`SECURITY.md`](SECURITY.md).

## License

By contributing you agree that your contribution is dual-licensed under
[MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE), as stated in the README.
