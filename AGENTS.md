# Repository operating contract for Codex

This file is a concise entry point to existing repository governance.
It does not redefine, replace, or grant exceptions to that governance.

## Canonical sources

Repository governance is defined by:

- `01_MASTER_SPEC.md`
- `config/AGENTS.yaml`
- `config/GATES.yaml`
- `config/NOTIFICATIONS.yaml`
- `config/PERMISSIONS.yaml`
- `config/POLICIES.yaml`
- The applicable `projects/<project>/PROJECT_RULES.yaml`
- The currently authorized Task Packet/instruction

Read the relevant canonical sources before implementation work.
If this file conflicts with a canonical governance file, that canonical
file controls: STOP and obtain clarification before proceeding.
Do not silently resolve conflicts or infer missing authorization.

## Authorized work

- Implement only the explicitly authorized task.
- Modify only the files authorized for that task.
- Do not touch governance/configuration files unless explicitly authorized.
- Do not expand scope, architecture, permissions, dependencies, data model,
  infrastructure, providers, or security behavior without express authorization.
- Preserve `MOTOR != RULES`: use the canonical sources for policy;
  do not invent policy in the engine or in this guidance file.
- Follow the approval boundaries and Human Gates in the canonical sources.

## Security

- Fail closed and apply least privilege.
- Never introduce secrets into code, prompts, logs, evidence, or databases.
- Do not bypass authorization or weaken security controls.
- Do not perform production or irreversible actions.
- Preserve tenant/client isolation when applicable.
- Apply the file, command, and tool restrictions in the canonical sources.

## Git and deployment

Git push is denied by default. Controlled task-branch publication and the exact
dedicated Safe Test source-tag action are defined in canonical YAML/spec,
requiring an explicit Task
Packet, Director approval, and every canonical restriction. The Builder must
never infer authorization from its role or capability alone.
Publishing main/master, generic force pushes, generic tags, remote deletion, and remotes or
repositories outside the exact allowlist remain prohibited. Git merge and
production remain absolutely prohibited. Do not rebase, reset, or clean
without express authorization consistent with canonical governance.
This section grants no independent exception; the canonical sources control.
Only git_publish_safe_test_source_tag may create the exact canonical trust tag,
when every permission, policy, gate, Builder capability, approved target and
verified protective Ruleset condition intersects. It never widens git_publish
or permits inferred tag authorization, tag updates or deletion.

## Verification and evidence

- Run only the tests required by the authorized Task Packet/instruction.
- Do not silently repair unrelated failures; report them to the Director.
- Report commands, results, failures, and verification limits factually.
- Do not treat agent narrative as proof when executable evidence is available.

## Stop and escalate

STOP if scope is ambiguous, rules conflict, unauthorized files would need
modification, a material unanticipated decision is required, or a security
control would need weakening. Escalate to the Director rather than choosing
an unapproved material alternative autonomously.

Report technical issues to the Director. Do not ask the Product Owner to
interpret code, choose shell commands, inspect diffs, or solve technical errors.
The Director translates material issues into business alternatives for the
Product Owner, following the canonical escalation and Human Gate rules.
