# FEP-2 (landed): Blueprints, the Credential Catalog, and On-Demand Discovery

**Formwork Enhancement Proposal 2 — landed in full.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

Everything this FEP proposed has been implemented, verified on real Seatbelt + the
unified-log denial feed, and **folded into `formwork.md`**:

- **spec → Blueprint rename** and the layered model — one typed schema, file + CLI
  surfaces, `extends`, override precedence, path sigils (`~`, `$CWD`):
  `formwork.md` §4 and §5.8 (FW-BP1–5).
- **The typed credential catalog** — locations only, two kinds enforced by two arms
  (path → confiner EACCES, env → launcher strip), exclude-by-type as the only un-deny,
  the generic backstop, the operator/agent channel split, and per-platform floor
  honesty: §5.9 (FW-CRED1–9). The catalog superseded FW-TRA3's informal sensitive set
  and now realizes FW-CAP3's subtractive default concretely.
- **The launcher as a third enforcement arm** — pre-spawn env construction, credential
  strip (absent, not denied), policy-input write-protection: §2 (architecture + diagram).
- **Observe-then-widen discovery** bounded by the catalog floor: §5.10 (FW-DISC1–6).
- **Invariants FW-INV7–10** (launcher-strip completeness, the credential floor,
  no-oracle, discovery non-authority): §6.
- **Tests FW-E2E-041–055 and FW-ADV-012–015**: §7.7–7.10, with traceability in §10 and
  the fidelity-matrix rows in §9.

The execution record — draft amendments (test-ID renumbering, the FW-BP2 layer-order
fix, FW-BP4 pinned to the FW-CAP6 grammar), the post-implementation requirements made
explicit (FW-BP5, FW-CRED9, the FW-DISC3/INV8 strengthening), the backstop-anchoring
review round and its revert, and the resolved open decisions (TOML stays;
observe-then-widen; curated catalog + backstop; auto-widen empty by default) — lives in
`docs/fep2-plan.md`. The full proposal text as adopted is in git history
(`git log -- fep2.md`, prior to the reintegration commit).

## Deferred beyond this FEP

- **Credential brokering** (interacts with FW-CRED5): whether the gateway should broker
  a credential's *use* without the agent ever seeing the bytes, instead of exclusion
  exposing the file/var. Safer, fits the single-privileged-broker shape, presupposes a
  secret-handling path through the broker — deferred to a later FEP and tracked as an
  open question in `formwork.md` §11.
- **Live interactive discovery prompting** (`SECCOMP_USER_NOTIF`/`ptrace`): a documented
  Linux-only future option; observe-then-widen is the shipped posture.
