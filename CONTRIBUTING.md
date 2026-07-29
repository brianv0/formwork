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
Landlock/seccomp) — they never silently pass. Run what your machine can enforce and let CI cover the
rest.

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

- [`formwork.md`](formwork.md) — the design and end-to-end test spec; the FW-* definitions.
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — how it is built (layout, phases, decisions).
- [`docs/STATUS.md`](docs/STATUS.md) — implementation status by phase.
- [`docs/`](docs/) — enhancement proposals (`fep-*.md`) and supporting design notes.

## Security

Please do not open public issues for vulnerabilities — see [`SECURITY.md`](SECURITY.md).

## License

By contributing you agree that your contribution is dual-licensed under
[MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE), as stated in the README.
