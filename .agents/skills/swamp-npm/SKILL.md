---
name: swamp-npm
description: >
  Use for deterministic npm install, audit, dependency query, SBOM, rebuild,
  package, and verification tasks with @funsaized/npm. Triggers on npm CI,
  package verification, dependency policy, SBOM, npm pack, and npm audit.
---

# Swamp npm

Use `@funsaized/npm/project` methods instead of direct `npm`, `npx`, or
`command/shell` execution.

1. Pin `packageManager` to an exact npm version and commit `package-lock.json`.
2. Pass `expectedGitHead` to every method in a delivery workflow.
3. Run `ci` before methods that inspect the installed dependency tree.
4. Keep lifecycle scripts denied. If native packages need install scripts, add
   only those package names to `allowedRebuildPackages` and call `rebuild`.
5. Use `query` for dependency policy and `list` for tree evidence.
6. Use `sbom` for CycloneDX or SPDX evidence.
7. Run `pack` in dry-run mode first. Set `dryRun: false` only when a tarball is
   required; publishing is intentionally unsupported.
8. Treat `audit` as time-bound registry evidence, not a reproducible result.

For complete verification, run the bundled `@funsaized/npm/verify` workflow
with `model` and the exact 40-character `expectedGitHead`.
