# myc — repository agent contract

## 1. Scope and operating model

- This file applies to the complete repository unless a nearer `AGENTS.md` is
  stricter.
- This repository owns `myc`, the standalone Radroots NIP-46 signer service.
  Treat identity custody, signing, approval, session, persistence, and
  signer-facing transport as security-critical behavior.
- Keep the repository independently buildable, testable, packageable, and
  operable. Do not depend on private repositories, unreachable or unlocked
  artifacts, internal monorepo paths, absolute workstation paths, or private
  harnesses. An unpublished public dependency is allowed only when its exact
  commit is reachable from the governed public Git source and pinned by the
  checked-in source lock.
- `.github/**` and capsule-local CI workflows are forbidden; keep validation
  forge-agnostic, and place any required monorepo orchestration exclusively
  under the parent monorepo's root `.act/**` authority.
- Do not add or retain tracked `docs/**`, `.github/**`, or `.act/**` content in
  this capsule. Human-facing Myc specifications, decisions, runbooks, and
  qualification evidence belong under the parent monorepo's
  `docs/oss/myc/**` authority; standalone machine-enforced declarations belong
  under this repository's governed contract surfaces.
- Myc does not own relay storage or tenancy, general relay fanout, SDK contract
  generation, wallet UX, hosted accounts, telemetry, artifact promotion, or
  deployment transport.

## 2. Authority and preflight

- Before editing, read this file, `README`, `Cargo.toml`,
  `radroots.lib.source-lock.v1.toml`, the relevant implementation and tests,
  and `flake.nix` or migrations when they are in scope.
- Treat checked-in source, tests, and prototype behavior as implementation
  evidence, not permission to preserve behavior that the active requirement
  removes.
- Do not invent protocol behavior, APIs, dependencies, release processes,
  identity authority, migration behavior, or external integration semantics.
- Inspect `git status --short`, the exact repository root, and nearby tests
  before changing behavior. Preserve unrelated work and stop on an unresolved
  security or custody conflict.
- Keep changes narrowly scoped and independently reviewable. Do not mix
  unrelated cleanup, speculative abstractions, roadmap work, or compatibility
  scaffolding into a checkpoint.

## 3. Clean-slate service rule

- Do not add or preserve prototype configuration readers, `.env` or
  `--env-file` runtime configuration, `MYC_*` runtime selectors, JSON/JSONL
  mutable state, prototype config/state importers or migrations, worker paths,
  old-path probes, aliases, fallbacks, dual readers/writers, deprecated
  modules/APIs/re-exports, or old/new feature switches. Offline production
  schema migration must never accept an unreleased prototype format.
- Remove superseded behavior and update every affected Radroots-owned consumer
  directly. Do not hide a breaking change behind a compatibility adapter unless
  an accepted public requirement explicitly requires one.
- Preserve canonical NIP-04, NIP-44, and NIP-46 interoperability. Clean-slate
  product behavior never authorizes protocol drift or relaxed wire validation.
- A breaking config, CLI, state, provider, admin, error, or wire change must
  update its public machine contracts, examples, tests, generated surfaces, and
  release qualification in the same coherent sequence.

## 4. Identity, provider, and secret boundaries

- Keep transport, user, and optional discovery identities explicit. Never
  generate, replace, infer, or collapse an identity during ordinary `run`.
- Support only the governed `encrypted_file` and permissioned Unix-socket
  `local_signer` providers. Do not add plaintext keys, arbitrary child
  commands, shells, desktop/server keyrings, managed accounts, TCP signers, or
  sibling wrapping-key fallback.
- Treat every provider result as untrusted. Verify contract version, operation
  and correlation IDs, expected identity and role, bounds, exact unsigned event
  fields, author, event ID, signature, and applicable NIP semantics before use.
- Keep plaintext keys, decrypted key material, wrapping credentials, provider
  secrets, and equivalent protected material out of config, logs, status,
  metrics, audit output, fixtures, backups, process arguments, environment
  contracts, error strings, and ordinary `Debug` output. A governed backup may
  contain the encrypted ciphertext envelope, but never the material needed to
  unwrap it. Minimize and zeroize protected values where practical.
- Use typed request, response, approval, permission, session, provider, and
  error models. Raw provider, relay, SQL, or source-chain errors never cross a
  public or operator boundary.

## 5. Configuration, state, and process boundaries

- Load exactly one immutable, strictly versioned TOML document. Reject unknown
  fields, implicit relays, unsafe defaults, environment overlays, includes,
  interpolation, fragments, hot reload, and arbitrary leaf flags.
- Each service instance owns one explicitly initialized SQLite catalog and one
  live writer lock. Normal `run` opens existing state only and never creates,
  imports, guesses, or silently migrates prototype state.
- Keep raw SQLite pools and write authority private to the store. The daemon is
  the only live writer; live mutations and online backup use the typed,
  permissioned Unix-socket admin boundary and never fall back to direct writes.
  Offline state operations must prove that no daemon writer lock is held.
- Never hold a database transaction while waiting for a provider, relay, DNS,
  clock, entropy, or other external effect.
- Parse the process CLI and initialize the tracing subscriber only in the
  binary composition boundary. Library modules may emit tracing events but
  must not install signal handlers, create nested Tokio runtimes, call
  `process::exit`, or detach authoritative tasks.
- Inject wall time, monotonic time, entropy, providers, transport, and
  failpoints. Supervise and join every authoritative task; panic, error, or
  unexpected successful return from a critical task must coordinate shutdown
  and produce a nonzero process result.

## 6. Admission, commit, and publication invariants

- Bound and validate signed event bytes, tags, authored time, recipient,
  signature, event ID, decrypted plaintext, request identity, method, replay,
  conflicting reuse, connection admission, authorization challenges, and rate
  retention before accepting work.
- Keep authorization-challenge URLs and display-only client metadata under
  operator policy; untrusted clients never choose redirect or display
  authority. Use separate bounded rate budgets for connection admission and
  authorization challenges so exhaustion of one cannot bypass or disable the
  other.
- Commit the request decision, session effects, audit, exact serialized signed
  response bytes, immutable target set, and initial outbox state atomically
  before any relay submission.
- Treat stored signed bytes as the sole publication authority. Retry, crash
  recovery, and reopen must submit the identical bytes and digest without
  deserializing, rebuilding, re-signing, or changing targets.
- Distinguish submitted, delivered, failed, and unknown outcomes. Lost
  acknowledgement never becomes proof of failure or delivery.
- Bound every queue, pool, request, response, event, tag set, retry schedule,
  deadline, rate window, retention set, audit query, and in-memory collection.
  Saturation must reject or defer safely without dropping committed work.

## 7. Admin and observability boundaries

- Detailed status and every live mutation use bounded, versioned HTTP/JSON over
  the permissioned Unix socket. Do not add TCP admin, browser auth, CORS, or a
  direct writable CLI fallback.
- Optional TCP operations expose only cached `/livez`, `/readyz`, and
  `/metrics`. They must not perform SQLite, provider, relay, credential, DNS,
  or other active probes.
- Keep logs as safe structured stderr output. Keep result data on stdout and
  diagnostics on stderr. Use stable bounded public codes and messages, bounded
  metric labels, and explicit redaction.
- Backup and restore must preserve lock, manifest, integrity, schema, service,
  instance, identity, permission, fsync, atomic-rename, and protected-material
  exclusion invariants.

## 8. Rust and test discipline

- Prefer pure transformations, explicit state machines, validated newtypes,
  tagged enums, narrow side-effect boundaries, and private visibility.
- Avoid hidden production panics. Use typed errors for expected failures and
  reserve `unwrap` or `expect` for tests or locally proven invariants.
- Keep `#![forbid(unsafe_code)]` at the crate roots; unsafe code is forbidden.
- Add deterministic positive, negative, boundary, crash/retry, cancellation,
  saturation, redaction, and interoperability tests for every behavior change.
  Tests and examples must not contain real secrets, realistic private keys,
  reusable credentials, or sensitive event content.
- Treat generated files as generated. Update them through the owning command
  and run the corresponding freshness check.

## 9. Canonical verification

Use the repository-owned Nix lanes as the standalone command authority:

```text
nix run .#fmt
nix run .#check
nix run .#test
nix run .#release-acceptance
```

The release-acceptance contract requires formatting, locked metadata, locked
all-target checking and testing, warnings-denied all-target Clippy, rustdoc with
warnings denied, and diff hygiene. Run any gate not yet covered by the current
release script explicitly; do not describe the script as sufficient until it
enforces the complete contract. Run additional SQLx freshness, source-lock,
Nix, OCI, systemd, package, SBOM, checksum, notice, and fresh-install gates when
their surfaces change. Use narrower checked-in commands only for iteration,
and never claim a command passed unless it ran successfully.

## 10. Commits and irreversible actions

- Format commits as `<scope>: <imperative summary>`, with a blank line and
  `- ` bullets when a body is useful. Split unrelated changes.
- Report the exact files changed, behavior changed, commands run, results,
  unresolved risks, and whether the next checkpoint is safe.
- Do not publish, push, tag, sign, deploy, rotate credentials, change ownership,
  or mutate trusted-publisher or external runtime state without explicit
  authorization for that exact action.
