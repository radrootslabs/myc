# myc - code directives

- this repo defines `myc`, the Radroots signer service
- treat signing, key material handling, approval flows, session control, and signer-facing transport as security-critical repo-owned behavior
- do not make this repo responsible for relay storage, relay fanout, relay tenancy, SDK contract generation, wallet product flows, platform-wide artifacts, publication, promotion, or deployment transport unless explicitly assigned here
- prefer the smallest coherent change that fully addresses the request; do not mix unrelated cleanup, speculative refactors, compatibility scaffolding, or roadmap work into the same change
- inspect the relevant implementation, tests, manifests, and docs before changing behavior
- do not invent requirements, APIs, dependencies, release processes, or external integration behavior
- do not depend on private repositories, unpublished artifacts, local machine layouts, absolute paths, or internal monorepo context
- keep key material handling narrow, explicit, auditable, and separated from presentation or transport glue
- prefer typed request, response, approval, session, and error models over stringly or implicit state
- keep public docs, manifests, tests, generated artifacts, and contract surfaces aligned with behavior changes
- avoid hidden production panics; use typed errors for expected failure modes
- avoid `unsafe` unless it is strictly necessary, locally justified, and documented with nearby invariants
- tests and examples must not include real secrets, realistic private keys, reusable credentials, or sensitive event content
- preserve least-privilege boundaries and explicit trust boundaries; stop and report concerns before weakening security, privacy, or key custody boundaries
- use checked-in, repo-owned validation first; run the smallest documented validation that credibly covers the change
- if validation cannot run, report exactly what was skipped and why; never claim validation passed unless it actually ran
- keep commits focused and reviewable, using `<scope>: <imperative summary>` unless a repo convention overrides it
