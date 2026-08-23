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
  `radroots.service.source-lock.v2.toml`, the relevant implementation and tests,
  and `flake.nix` or migrations when they are in scope.
- `.radroots-consumer-root` is the standalone source-lock identity and must
  remain exactly `myc`. The implemented control-plane contract is
  `contracts/services_hardening/operator_contract.v1.json`.
  Service implementation must use its exact routes, operation IDs, model
  fields, doctor checks, and shared host/exit references; prototype CLI or
  HTTP behavior is not authority to reinterpret that contract.
- The exact signer-provider inventory and resource boundary is
  `contracts/services_hardening/provider_contract.v1.json`. Keep its role,
  provider, capability, call-identity, deadline, limit, credential-reference,
  cancellation, and no-publication facts synchronized with the sealed Rust
  models. Provider wire encoding and result verification may refine only the
  later checkpoints that own those boundaries; they may not widen this
  contract.
- The encrypted-file implementation is frozen by
  `contracts/services_hardening/encrypted_identity_envelope.v1.json`. It must
  use the source-locked `radroots_secrets` v2 context-bound envelope, explicit
  caller-supplied entropy, create-new owner-only persistence, expected-public-
  key verification, and state-backup exclusion. Credential artifact resolution
  remains a separate boundary and may not introduce a sibling-key fallback.
- Wrapping-credential resolution is frozen by
  `contracts/services_hardening/wrapping_credential_resolution.v1.json`. It
  derives one validated shared artifact name beneath the canonical instance
  secrets root, reads only an existing exact owner-only artifact, and exposes
  neither a caller path nor caller bytes. Production injection/mounting and
  repo-local provisioning are external/offline; ordinary run, TOML,
  environment, arguments, envelope siblings, and state backup never create or
  carry the credential.
- Local-signer transport is frozen by
  `contracts/services_hardening/local_signer_transport.v1.json`. It uses the
  hardened Lib `AdminClient` for one fixed HTTP/1.1 JSON endpoint over a Unix
  socket, carries the complete provider-operation binding in closed tagged
  request/response models, enforces configured body/deadline/concurrency
  limits, and returns only semantically untrusted output for Step 135.
- Provider verification is frozen by
  `contracts/services_hardening/provider_verification.v1.json`. It requires
  injected observation time, rebinds the complete response to the configured
  provider and original operation, verifies peer/direction/version and exact
  protocol shapes, cryptographically verifies signed events, retains their
  exact canonical bytes, and returns only a sealed redacted result.
  Verification is not publication and performs no provider execution or
  database mutation.
- Step 136 removes the orphaned prototype provider tree and its keyring,
  managed-account, plaintext/adjacent-key, child-process, implicit-identity,
  generic remote-session, legacy logging/client, and unused dependency
  surfaces. Do not restore those files, dependencies, or Tokio process
  capability; `radroots_nostr_connect` remains only as the active NIP-46
  protocol dependency.
- Step 137 owns only the existing-state runtime foundation and exact startup
  prerequisite inventory. Encrypted-file opening runs in joined one-shot
  supervisor tasks; local-signer construction performs no probe, and no
  provider is ready before its governed verification. Do not add detached
  handles, a library runtime, signals, process exit, relay/admin execution, or
  a false readiness transition here.
- Step 138 freezes a root-only public API. Keep every implementation module
  private, expose only curated crate-root names, keep public errors crate-owned
  and source-free, and update the reviewed API baseline and package guards for
  every intentional public-surface change. Shared runtime-path, SQLite, and
  storage identity types are deliberate governed contract dependencies;
  provider, SQLx, Serde, transport, and task implementation types are not.
- Step 139 established the predecessor service source lock and pre-promotion
  native package metadata. Keep the exact Lib revision consistent across every
  direct Radroots dependency, Cargo.lock, the verified source archive, and the
  generated v2 service lock. Deferred `flake.nix` and `flake.lock` material is
  independently digest-bound and may select an older reachable Lib revision;
  it is not active native revision authority. Native target metadata does not
  qualify an artifact; Nix, OCI, signing, tags, publication, and deployment
  remain deferred.
- Step 148 closes the production NIP-46 response authority in
  `contracts/services_hardening/nip46_response_commit.v1.json`. Production
  code may commit a completion only through the atomic exact-response method;
  a retained completion without its immutable response and initial delivery
  state is inconsistent evidence and must never be repaired implicitly.
- Step 150 introduced the historical 21-route and 35-model Myc Unix-admin
  adapter. Step 159 unit 13 owns its final 19-route and 32-model form by
  removing live identity rekey and replacement. Keep the shared Lib router
  private; reject model drift, unknown/duplicate/null
  fields, noncanonical response bytes, invalid path/query values, and unsafe
  errors at the adapter boundary. Domain handlers must bind authenticated
  cursors to route/filter/snapshot identity and must retain exact operation-ID
  replay/conflict evidence before returning success. Do not infer relay
  delivery from a successful local mutation and do not add TCP admin routes.
- Step 152 freezes the one-parse CLI execution split. Every admitted command
  must select exactly daemon, offline, or permissioned Unix-admin authority;
  only the explicitly contracted read-only status, backup, and public-identity
  operations may fall back after proving the daemon writer lock is free.
  Identity rekey and replacement are offline create-new/config-apply
  operations and have no live command or route. Every retained live mutation
  has no direct-state fallback.
  Do not reparse process arguments or let a live CLI plan obtain SQLite,
  provider, relay, task, signal, or runtime authority.
- Step 153 freezes one ordered 13-check doctor engine. Check adapters retain
  their operation-specific authority and may return only closed observations;
  the engine owns exact deadlines, required/optional aggregation, fixed safe
  summaries/remediation codes, bounded canonical JSON, and exit 6 for required
  failure or timeout. Do not admit raw errors, paths, URLs, keys, credentials,
  arbitrary details, unbounded output, detached probe work, or
  liveness/readiness probe authority. A pass must prove every contracted scope
  facet, and deadline cancellation must stop or synchronously own cleanup.
- Step 154 freezes one passive latest-value status cache around the shared Lib
  lifecycle primitive. The non-clone publisher encodes the complete bounded v1
  local-status envelope before atomic replacement; cloneable readers may only
  return the retained immutable snapshot. Status reads never query SQLite,
  providers, relays, credentials, DNS, time, or fresh probes and never spawn a
  task. Keep connection-count keys and identity roles closed, preserve the last
  valid snapshot on any failed publication, admit only the fixed twelve status
  reasons, and keep detailed status on the permissioned Unix-admin boundary.
- Step 159 unit 10 owns schema-v10 offline configuration lifecycle. Keep the
  configuration-binding ledger append-only and capped at 1,024 generations;
  seed one post-migration generation without rewriting the immutable birth
  record. Startup must match the latest config/public-identity binding. Identity
  changes revoke live connection/challenge authority, permission narrowing
  revokes affected sessions only, and an existing relay referenced by
  nonterminal delivery work cannot be removed or changed. Do not persist relay
  URLs, paths, credentials, provider envelopes, or protected values in the
  binding history.
- Step 159 unit 11 owns schema-v11 bounded admin idempotency. Keep operation
  identifiers on the fixed ASCII grammar, bind route plus canonical request
  digest, cap replay models at 8,192 bytes, prune only expired Completed rows,
  reserve completion capacity at admission, and retain unresolved Prepared
  evidence as outcome-unknown. The configured admin response cap must admit the
  maximum model in its bounded success envelope. Never persist a
  request body, path, correlation ID, credential, bundle path, or secret in the
  journal. Database-only mutations must later compose their effect, audit, and
  completion in one transaction; online backup records Prepared before capture
  and completes only after the bundle is durable.
- Step 159 unit 12 owns the crate-private provider executor, the exact
  source-locked `radroots_transport_nostr` adapter, and the durable delivery
  worker. Provider results remain untrusted until independently verified.
  Delivery preparation performs no relay I/O; the worker persists Submitted
  immediately before execution, maps post-submit cancellation or lost
  acknowledgement to UnknownAcknowledgement, and retries only the exact
  committed signed bytes. Never hold a SQLite transaction across provider or
  relay work, detach protected blocking work, expose the executor/client, or
  create one task per relay. Unit 15 alone wires these components into the
  fixed runtime graph and startup handshake.
- Step 159 unit 13 owns the final 19-route/32-model production Unix-admin
  server around the exact handler boundary, the configured transport-limit
  projection, the canonical permissioned `admin.sock` binding, and the
  machine-bound composition facts for the existing sole status publisher,
  passive three-route operations server, and injected 13-check doctor. Keep
  shared routers, listeners, entropy, and cancellation private. Unit 14 owns
  secure CLI/config bootstrap and concrete doctor probes; Unit 15 alone owns
  server task spawning, provider/relay wiring, readiness, reconnect, and
  shutdown.
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
- Keep the Myc critical-task graph bounded and sealed. A task receives only its
  cooperative cancellation observer; callers cannot name tasks, extract task
  handles, detach work, install signals, or select process exits through this
  library boundary. Step 159 owns signal and forced-shutdown composition.

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
- Create delivery jobs only inside the atomic signed-response or discovery
  transaction. Recovery is a bounded, cursor-driven repository operation with
  injected time/jitter evidence; final supervised startup looping remains a
  later runtime owner.
- Render NIP-05 only from verified committed discovery state through an
  explicit desired/current offline operation. The service library must not
  silently host the document or acquire network authority while rendering it.
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
- Keep the Myc TCP adapter sealed around the source-locked service-host server.
  Do not add route registration, raw listener/server access, dependency-owned
  public types, or a second independently observed lifecycle cache. Publish
  only the fixed cached phase/readiness metric families and closed phase label.
- Keep logs as safe structured stderr output. Keep result data on stdout and
  diagnostics on stderr. Use stable bounded public codes and messages, bounded
  metric labels, and explicit redaction.
- Emit only the sealed `MycLogRecord` vocabulary. Do not log caller text, raw
  errors or sources, paths, SQL, relay URLs, identifiers, credentials,
  protected content, or decrypted payloads. Keep the exact 0-6 process result
  mapping synchronized with the operator contract; do not call process exit
  from library code or add file logging.
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

Through RCLD-RSHR-170, run the standalone native command authority through
extbuild. Do not install, repair, invoke, or require Nix, and do not claim Nix,
NixOS-module, or Nix-produced OCI qualification:

```text
cargo extbuild doctor
cargo extbuild run -- cargo fmt --all --check
cargo extbuild run -- cargo check --workspace --locked
cargo extbuild run -- cargo test --workspace --all-targets --locked
cargo extbuild run -- cargo clippy --workspace --all-targets --locked -- -D warnings
cargo extbuild run -- ./scripts/release-acceptance.sh
```

The release-acceptance contract requires formatting, locked metadata, locked
all-target checking and testing, warnings-denied all-target Clippy, rustdoc with
warnings denied, and diff hygiene. Run any gate not yet covered by the current
release script explicitly; do not describe the script as sufficient until it
enforces the complete contract. Run additional SQLx freshness, source-lock,
systemd, package, SBOM, checksum, notice, and fresh-install gates when their
surfaces change. Checked-in Nix material remains deferred source data through
RCLD-RSHR-170 and is not a verification gate. Every OCI production or
qualification path is likewise deferred and unclaimed through RCLD-RSHR-170.
Use narrower checked-in commands only for iteration, and never claim a command
passed unless it ran successfully.

## 10. Commits and irreversible actions

- Format commits as `<scope>: <imperative summary>`, with a blank line and
  `- ` bullets when a body is useful. Split unrelated changes.
- Report the exact files changed, behavior changed, commands run, results,
  unresolved risks, and whether the next checkpoint is safe.
- Do not publish, push, tag, sign, deploy, rotate credentials, change ownership,
  or mutate trusted-publisher or external runtime state without explicit
  authorization for that exact action.
