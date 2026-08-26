# @funsaized/npm

Typed, reproducible npm project operations for [Swamp](https://swamp-club.com).
The extension invokes `node`, `npm`, and read-only `git` commands directly with
`Deno.Command`; it never constructs a shell command.

## Install

```bash
swamp extension pull @funsaized/npm
swamp model create @funsaized/npm/project my-project
```

Configure the generated model with a repository-relative `projectDir`. Strict
toolchain mode is enabled by default:

```yaml
globalArguments:
  projectDir: .
  strictToolchain: true
  configPolicy: project
  lifecycleScripts: deny
  allowedScripts:
    - check
    - build
  environment: {}
  defaultTimeoutMs: 900000
  requireCleanGit: true
```

## Toolchain Policy

npm identity comes from `package.json#packageManager` (`npm@<exact-version>`) or
`expectedNpmVersion`. When both are present they must agree. Strict mode rejects
a project when neither source exists. The actual npm version must also satisfy
`engines.npm` when declared.

The actual Node version must satisfy `engines.node` and, when supplied,
`expectedNodeVersion`. The latter accepts an exact version or semver range.
`.nvmrc` is ignored.

## Lifecycle Policy

`lifecycleScripts: deny` is the default. `ci` then runs the equivalent of:

```text
npm ci --ignore-scripts --no-audit --no-fund
```

This blocks install lifecycle scripts but does not block explicit `run` calls.
Set `lifecycleScripts: allow` only when the project explicitly requires install
scripts; the choice is recorded in every invocation.

## Methods

| Method    | Contract |
| --------- | -------- |
| `inspect` | Records package metadata, scripts, workspaces, lockfile state, configuration hashes, tool versions, lifecycle policy, and optional Git head. |
| `ci`      | Requires a lockfile and runs reproducible `npm ci`; supports omit/include, install strategy, strict peers, dry-run, workspace selection, and exact Git head. |
| `run`     | Runs an existing package script, enforcing `allowedScripts` when configured. Arguments are passed as argv after `--`. |
| `list`    | Stores redacted raw `npm ls --json` output and a normalized dependency tree. |
| `audit`   | Stores redacted raw `npm audit --json` output and separately records execution, findings, and policy status before failing policy. |

All methods accept `expectedGitHead` so evidence can be tied to a reviewed
commit. Workspace-capable methods accept `workspaces` and
`includeWorkspaceRoot`.

## Evidence And Failures

Every call stores a redacted streaming log and an `invocation` resource with
operation, argv, repository-relative project path, timing, exit status,
toolchain, platform, workspace selection, lifecycle policy, environment key
names, manifest hashes, npm configuration hash, and before/after Git state.

Swamp preserves completed writes when a method subsequently throws. The model
uses that contract deliberately: command or policy failures write invocation
evidence first and then throw, so model methods and workflows fail closed while
the failure remains inspectable. `audit` also writes its structured report
before applying `failOnFindings`.

```bash
swamp data query '<CEL predicate>' --json
swamp report get @swamp/method-summary --model my-project --json
```

## npm Configuration

`configPolicy: project` removes inherited `NPM_CONFIG_*` values and points npm's
user and global configuration at an empty temporary file. A committed project
`.npmrc` remains active. Only its SHA-256 hash is recorded; contents are never
stored. Explicit environment additions are allowed, but evidence records only
their names and known values are redacted from argv, logs, errors, and raw JSON.

## Workspaces

Pass one or more npm workspace names or paths:

```bash
swamp model method run my-project run \
  --input script=check \
  --input 'workspaces=["packages/app"]'
```

The extension forwards each selection as a separate `--workspace` argument and
records the selection in invocation evidence.

## Security Boundaries

- `projectDir` must exist, resolve inside `context.repoDir`, and cannot escape
  through `..`, an absolute path, or a symlink.
- Commands use fixed executable names and argv arrays, never a shell command.
- Lifecycle scripts are denied during `ci` unless explicitly allowed.
- User/global npm configuration and inherited npm overrides are isolated.
- Environment values and `.npmrc` contents are never persisted.
- Processes honor cancellation and the configured timeout.
- Logs stream to Swamp storage; captured command output is bounded at 64 MiB.
- Git head and clean tracked-worktree invariants are checked before and after
  execution when configured.

## Deferred Methods

The extension intentionally does not expose package mutation, registry
mutation, arbitrary execution, or release methods. This excludes `install`,
`uninstall`, `update`, `dedupe`, `prune`, `audit_fix`, `outdated`, `exec`, all
`pkg_*` methods, `version`, `pack`, and `publish`.

## Development

```bash
~/.swamp/deno/deno fmt --check models/*.ts
~/.swamp/deno/deno check models/project.ts models/project_test.ts
~/.swamp/deno/deno test --allow-env --allow-read --allow-write --allow-run models/project_test.ts
swamp doctor extensions --json
swamp extension push manifest.yaml --dry-run
```

Licensed under MIT.
