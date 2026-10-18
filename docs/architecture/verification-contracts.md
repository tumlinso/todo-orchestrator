# Authored verification contracts

An exact work-definition version owns its requirements. A check requirement may
carry a `VerificationContract` and named `EvidenceRequirement` entries. They are
data describing acceptance criteria; trusted providers perform the observations
and effects. No plan selects a Python callback or provider import path.

The version 1 tagged contract supports:

| Kind | Authored criterion |
| --- | --- |
| `command` | Argument vector, relative working directory, bounded timeout and expected exit codes |
| `file` | Relative path with existence, absence or SHA-256 predicate |
| `artifact` | Artifact kind with existence or exact digest predicate |
| `benchmark` | Named metric, comparison, finite threshold, unit and minimum sample count |
| `predicate` | Named, versioned comparison over bounded JSON data |
| `interface` | Interface ID, numeric version and compatibility policy |
| `checkpoint` | Checkpoint ID and required reached/accepted state |
| `manual_owner` | Approver role and exact actor incarnation |
| `domain_provider` | Provider ID/version, contract ID/version and bounded parameters |

Unknown kinds, versions, fields, unsupported predicates and unsafe relative
paths fail validation. `VerificationContract.from_mapping` normalizes authored
JSON; `to_mapping` produces its canonical reloadable form. Required evidence
entries bind a name, typed evidence kind and version. Configurations are frozen
and bounded; command arguments are an argument array, not a shell expression.

Compilation, partial revision masks, definition fingerprints, accepted snapshots
and normalized SQLite requirement rows retain these fields. Changing a check or
its evidence contract changes its owning definition bundle. Committing such a
change requires `todo.plan.commit` authority, current reviewed revision and
changeset digest, and the existing active/accepted-definition guards. An
attempt-only worker grant cannot weaken the authored checks.

Prerequisite groups and explicit blocking dependencies govern admission. Check
groups describe acceptance criteria: they must not prevent a fresh attempt from
being claimed to perform the checks. Advisory eligibility and transactional
claim use the same distinction. Final acceptance must enforce the check groups;
an unobserved check is not a pass.

`OutcomeDisposition.NO_CHANGE`, `EVALUATED_NOT_PROMOTED`, `ACCEPTED_NEGATIVE` and
`FAILED` are distinct values. An allowed scientific negative result does not
become a failed process, and process exit success does not accept an outcome.
Runtime verification and final source applicability remain separate operations.

Schema 9 stores typed requirement contracts and the added outcome disposition.
Earlier development schemas fail closed; this is not a legacy or production
authority migration. Tests establish contract validation, authenticated plan
commit, exact snapshot reopening, stored projection preservation and refusal of
unauthorized weakening. They do not establish actual runner execution or final
outcome acceptance.
