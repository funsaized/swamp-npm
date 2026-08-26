/// <reference lib="deno.ns" />
import { model, testing } from "./project.ts";

type Resource = {
  specName: string;
  name: string;
  data: Record<string, unknown>;
};
type File = { specName: string; name: string; text: string };

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function rejects(fn: () => Promise<unknown>, includes: string) {
  let message = "";
  try {
    await fn();
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  assert(
    message.includes(includes),
    `Expected "${includes}", got "${message}"`,
  );
}

async function command(cwd: string, executable: string, ...args: string[]) {
  const output = await new Deno.Command(executable, {
    cwd,
    args,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!output.success) throw new Error(new TextDecoder().decode(output.stderr));
  return new TextDecoder().decode(output.stdout).trim();
}

async function copyDirectory(source: string, destination: string) {
  await Deno.mkdir(destination, { recursive: true });
  for await (const entry of Deno.readDir(source)) {
    const from = `${source}/${entry.name}`;
    const to = `${destination}/${entry.name}`;
    if (entry.isDirectory) await copyDirectory(from, to);
    else if (entry.isFile) await Deno.copyFile(from, to);
    else if (entry.isSymlink) await Deno.symlink(await Deno.readLink(from), to);
  }
}

async function fixture(name: string) {
  const root = await Deno.makeTempDir({ prefix: `swamp-npm-${name}-` });
  const source = new URL(`./fixtures/${name}`, import.meta.url).pathname;
  await copyDirectory(source, root);
  return root;
}

async function initGit(root: string) {
  await command(root, "git", "init", "-b", "master");
  await command(root, "git", "add", ".");
  await command(
    root,
    "git",
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.com",
    "commit",
    "-m",
    "fixture",
  );
  return await command(root, "git", "rev-parse", "HEAD");
}

function testContext(
  repoDir: string,
  overrides: Partial<{
    projectDir: string;
    lifecycleScripts: "deny" | "allow";
    allowedScripts: string[];
    environment: Record<string, string>;
    defaultTimeoutMs: number;
    requireCleanGit: boolean;
    expectedNpmVersion: string | undefined;
    expectedNodeVersion: string | undefined;
    strictToolchain: boolean;
    signal: AbortSignal;
  }> = {},
) {
  const resources: Resource[] = [];
  const files: File[] = [];
  const context = {
    signal: overrides.signal ?? new AbortController().signal,
    repoDir,
    globalArgs: {
      projectDir: overrides.projectDir ?? ".",
      expectedNpmVersion: "expectedNpmVersion" in overrides
        ? overrides.expectedNpmVersion
        : "11.19.0",
      expectedNodeVersion: "expectedNodeVersion" in overrides
        ? overrides.expectedNodeVersion
        : ">=24",
      strictToolchain: overrides.strictToolchain ?? true,
      configPolicy: "project" as const,
      lifecycleScripts: overrides.lifecycleScripts ?? "deny",
      allowedScripts: overrides.allowedScripts ?? [],
      environment: overrides.environment ?? {},
      defaultTimeoutMs: overrides.defaultTimeoutMs ?? 30_000,
      requireCleanGit: overrides.requireCleanGit ?? false,
    },
    writeResource(
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) {
      resources.push({ specName, name, data: structuredClone(data) });
      return Promise.resolve({ name });
    },
    createFileWriter(specName: string, name: string) {
      let text = "";
      let finalized = false;
      const persist = () => {
        if (!finalized) {
          files.push({ specName, name, text });
          finalized = true;
        }
        return { name };
      };
      return {
        writeLine(line: string) {
          text += `${line}\n`;
          return Promise.resolve();
        },
        writeText(value: string) {
          text = value;
          return Promise.resolve(persist());
        },
        finalize() {
          return Promise.resolve(persist());
        },
      };
    },
    logger: { info() {}, error() {} },
  };
  return { context, resources, files };
}

const workspaceDefaults = { workspaces: [], includeWorkspaceRoot: false };

Deno.test("inspect records metadata and hashes without configuration contents", async () => {
  const root = await fixture("basic");
  const secret = "fixture-registry-token";
  await Deno.writeTextFile(
    `${root}/.npmrc`,
    `//registry.example.com/:_authToken=${secret}\n`,
  );
  try {
    const { context, resources, files } = testContext(root);
    await model.methods.inspect.execute({}, context);
    const project = resources.find((item) => item.specName === "project");
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(project?.data.npmrcSha256, "Expected an .npmrc hash");
    assert(
      invocation?.data.executionStatus === "succeeded",
      "Inspect did not succeed",
    );
    assert(
      !JSON.stringify({ resources, files }).includes(secret),
      "Credential leaked into persisted evidence",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("ci succeeds with a synchronized lockfile", async () => {
  const root = await fixture("basic");
  try {
    const { context, resources } = testContext(root);
    await model.methods.ci.execute({
      ...workspaceDefaults,
      omit: [],
      include: [],
      strictPeerDeps: false,
      dryRun: false,
    }, context);
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      invocation?.data.executionStatus === "succeeded",
      "ci did not succeed",
    );
    assert(
      invocation.data.lifecyclePolicy === "deny",
      "deny policy was not recorded",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("failed ci preserves invocation evidence and still throws", async () => {
  const root = await fixture("mismatched-lockfile");
  try {
    const { context, resources } = testContext(root);
    await rejects(
      () =>
        model.methods.ci.execute({
          ...workspaceDefaults,
          omit: [],
          include: [],
          strictPeerDeps: false,
          dryRun: false,
        }, context),
      "npm ci",
    );
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      invocation?.data.executionStatus === "failed",
      "Failure evidence was not written",
    );
    assert(
      typeof invocation.data.exitCode === "number",
      "Failure exit code was not recorded",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("ci denies lifecycle scripts by default and runs them only when allowed", async () => {
  const denied = await fixture("lifecycle-script");
  const allowed = await fixture("lifecycle-script");
  const args = {
    ...workspaceDefaults,
    omit: [],
    include: [],
    strictPeerDeps: false,
    dryRun: false,
  };
  try {
    await model.methods.ci.execute(args, testContext(denied).context);
    assert(
      !(await fileExists(`${denied}/postinstall.marker`)),
      "deny mode ran postinstall",
    );
    await model.methods.ci.execute(
      args,
      testContext(allowed, { lifecycleScripts: "allow" }).context,
    );
    assert(
      await fileExists(`${allowed}/postinstall.marker`),
      "allow mode skipped postinstall",
    );
  } finally {
    await Deno.remove(denied, { recursive: true });
    await Deno.remove(allowed, { recursive: true });
  }
});

Deno.test("run enforces allowlist and rejects unknown scripts", async () => {
  const root = await fixture("basic");
  try {
    const allowed = testContext(root, { allowedScripts: ["ok"] });
    await model.methods.run.execute({
      ...workspaceDefaults,
      script: "ok",
      args: [],
      ifPresent: false,
    }, allowed.context);
    assert(await fileExists(`${root}/ok.marker`), "Allowed script did not run");
    await rejects(
      () =>
        model.methods.run.execute({
          ...workspaceDefaults,
          script: "args",
          args: [],
          ifPresent: false,
        }, allowed.context),
      "not allowed",
    );
    await rejects(
      () =>
        model.methods.run.execute({
          ...workspaceDefaults,
          script: "missing",
          args: [],
          ifPresent: false,
        }, testContext(root).context),
      "Unknown package script",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("run passes shell syntax as one argument", async () => {
  const root = await fixture("basic");
  try {
    const argument = "; touch extension-interpreted-this";
    await model.methods.run.execute({
      ...workspaceDefaults,
      script: "args",
      args: [argument],
      ifPresent: false,
    }, testContext(root, { allowedScripts: ["args"] }).context);
    const recorded = JSON.parse(await Deno.readTextFile(`${root}/args.json`));
    assert(
      recorded[0] === argument,
      "Argument changed before reaching the script",
    );
    assert(
      !(await fileExists(`${root}/extension-interpreted-this`)),
      "Argument was interpreted as shell syntax by the extension",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("project path escapes and symlink escapes are rejected", async () => {
  const root = await fixture("basic");
  const outside = await fixture("basic");
  try {
    await rejects(
      () => testing.resolveProject(root, ".."),
      "escapes the repository",
    );
    await Deno.symlink(outside, `${root}/linked-outside`);
    await rejects(
      () => testing.resolveProject(root, "linked-outside"),
      "escapes the repository",
    );
    await rejects(
      () => testing.resolveProject(root, outside),
      "must be relative",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
    await Deno.remove(outside, { recursive: true });
  }
});

Deno.test("Git head mismatch fails before npm execution", async () => {
  const root = await fixture("basic");
  try {
    await initGit(root);
    const { context, resources } = testContext(root);
    await rejects(
      () =>
        model.methods.ci.execute({
          ...workspaceDefaults,
          omit: [],
          include: [],
          strictPeerDeps: false,
          dryRun: false,
          expectedGitHead: "a".repeat(40),
        }, context),
      "Git head mismatch",
    );
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      invocation?.data.exitCode === null,
      "npm ran before the head mismatch failed",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("tracked package and lockfile changes fail the clean Git invariant", async () => {
  for (const script of ["mutate-package", "mutate-lock"]) {
    const root = await fixture("basic");
    try {
      await initGit(root);
      const { context, resources } = testContext(root, {
        allowedScripts: [script],
        requireCleanGit: true,
      });
      await rejects(
        () =>
          model.methods.run.execute({
            ...workspaceDefaults,
            script,
            args: [],
            ifPresent: false,
          }, context),
        "Tracked Git worktree changed",
      );
      const invocation = resources.find((item) =>
        item.specName === "invocation"
      );
      assert(
        invocation?.data.cleanWorktreeAfter === false,
        `${script} change was not recorded`,
      );
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  }
});

Deno.test("workspace selection targets the selected workspace", async () => {
  const root = await fixture("workspace");
  try {
    await model.methods.ci.execute({
      ...workspaceDefaults,
      omit: [],
      include: [],
      strictPeerDeps: false,
      dryRun: false,
    }, testContext(root).context);
    await model.methods.run.execute({
      workspaces: ["workspace-app"],
      includeWorkspaceRoot: false,
      script: "mark",
      args: [],
      ifPresent: false,
    }, testContext(root, { allowedScripts: ["mark"] }).context);
    assert(
      await fileExists(`${root}/packages/app/workspace.marker`),
      "Selected workspace script did not run",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("timeout stops the process and records failure", async () => {
  const root = await fixture("basic");
  try {
    const { context, resources } = testContext(root, {
      allowedScripts: ["sleep"],
      defaultTimeoutMs: 1_000,
    });
    await rejects(
      () =>
        model.methods.run.execute({
          ...workspaceDefaults,
          script: "sleep",
          args: [],
          ifPresent: false,
        }, context),
      "timed out",
    );
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      invocation?.data.executionStatus === "failed",
      "Timeout evidence missing",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("list persists raw JSON and a normalized dependency tree", async () => {
  const root = await fixture("basic");
  try {
    await model.methods.ci.execute({
      ...workspaceDefaults,
      omit: [],
      include: [],
      strictPeerDeps: false,
      dryRun: false,
    }, testContext(root).context);
    const { context, resources, files } = testContext(root);
    await model.methods.list.execute({
      ...workspaceDefaults,
      all: true,
    }, context);
    assert(
      resources.some((item) => item.specName === "dependencyTree"),
      "Tree missing",
    );
    assert(
      files.some((item) => item.specName === "rawJson"),
      "Raw JSON missing",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("audit persists clean execution, findings, and policy states", async () => {
  const root = await fixture("basic");
  try {
    const { context, resources, files } = testContext(root);
    await model.methods.audit.execute({
      ...workspaceDefaults,
      auditLevel: "low",
      omit: [],
      include: [],
      failOnFindings: true,
    }, context);
    const report = resources.find((item) => item.specName === "auditReport");
    assert(
      report?.data.executionStatus === "succeeded",
      "Audit execution failed",
    );
    assert(
      report.data.findingsStatus === "clean",
      "Clean audit reported findings",
    );
    assert(report.data.policyStatus === "passed", "Clean audit failed policy");
    assert(
      files.some((item) => item.specName === "rawJson"),
      "Raw audit JSON missing",
    );

    const normalized = testing.normalizeAudit({
      vulnerabilities: {
        example: {
          severity: "high",
          isDirect: true,
          range: "<2.0.0",
          via: ["Example advisory"],
          fixAvailable: true,
        },
      },
      metadata: { vulnerabilities: { high: 1, total: 1 } },
    });
    assert(
      normalized.findings.length === 1,
      "Audit finding normalization failed",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("environment values are redacted while key names are retained", async () => {
  const root = await fixture("basic");
  const secret = "explicit-fixture-secret";
  try {
    const { context, resources, files } = testContext(root, {
      allowedScripts: ["args"],
      environment: { TEST_SECRET: secret },
    });
    await model.methods.run.execute({
      ...workspaceDefaults,
      script: "args",
      args: [secret],
      ifPresent: false,
    }, context);
    const persisted = JSON.stringify({ resources, files });
    assert(!persisted.includes(secret), "Explicit environment value leaked");
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      JSON.stringify(invocation?.data.environmentKeys) === '["TEST_SECRET"]',
      "Environment key evidence missing",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("inherited npm configuration is stripped and explicit environment is retained", async () => {
  const root = await fixture("basic");
  const previous = Deno.env.get("NPM_CONFIG_REGISTRY");
  const previousToken = Deno.env.get("GITHUB_TOKEN");
  Deno.env.set("NPM_CONFIG_REGISTRY", "https://inherited.example.com");
  Deno.env.set("GITHUB_TOKEN", "ambient-secret-must-not-be-forwarded");
  try {
    await model.methods.run.execute(
      {
        ...workspaceDefaults,
        script: "env",
        args: [],
        ifPresent: false,
      },
      testContext(root, {
        allowedScripts: ["env"],
        environment: { EXPLICIT_TEST_VALUE: "present" },
      }).context,
    );
    const output = JSON.parse(await Deno.readTextFile(`${root}/env.json`));
    assert(
      output.inherited !== "https://inherited.example.com",
      "Inherited NPM_CONFIG_REGISTRY reached npm",
    );
    assert(output.ambientSecret === null, "Ambient host secret reached npm");
    assert(
      output.explicit === "present",
      "Explicit environment value was removed",
    );
  } finally {
    if (previous === undefined) Deno.env.delete("NPM_CONFIG_REGISTRY");
    else Deno.env.set("NPM_CONFIG_REGISTRY", previous);
    if (previousToken === undefined) Deno.env.delete("GITHUB_TOKEN");
    else Deno.env.set("GITHUB_TOKEN", previousToken);
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("an already-aborted signal prevents command launch and records evidence", async () => {
  const root = await fixture("basic");
  const controller = new AbortController();
  controller.abort();
  try {
    const { context, resources } = testContext(root, {
      signal: controller.signal,
    });
    await rejects(
      () => model.methods.inspect.execute({}, context),
      "cancelled before launch",
    );
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      invocation?.data.executionStatus === "failed",
      "Cancellation evidence missing",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("strict toolchain requires npm identity and validates Node engines", async () => {
  const noIdentity = await fixture("basic");
  const badEngine = await fixture("basic");
  try {
    const noIdentityPackage = JSON.parse(
      await Deno.readTextFile(`${noIdentity}/package.json`),
    );
    delete noIdentityPackage.packageManager;
    await Deno.writeTextFile(
      `${noIdentity}/package.json`,
      `${JSON.stringify(noIdentityPackage, null, 2)}\n`,
    );
    await rejects(
      () =>
        model.methods.inspect.execute(
          {},
          testContext(noIdentity, {
            expectedNpmVersion: undefined,
          }).context,
        ),
      "strictToolchain requires",
    );

    const badEnginePackage = JSON.parse(
      await Deno.readTextFile(`${badEngine}/package.json`),
    );
    badEnginePackage.engines = { node: "<1" };
    await Deno.writeTextFile(
      `${badEngine}/package.json`,
      `${JSON.stringify(badEnginePackage, null, 2)}\n`,
    );
    await rejects(
      () => model.methods.inspect.execute({}, testContext(badEngine).context),
      "does not satisfy <1",
    );
  } finally {
    await Deno.remove(noIdentity, { recursive: true });
    await Deno.remove(badEngine, { recursive: true });
  }
});

Deno.test("npm launch failure records failed invocation evidence", async () => {
  const root = await fixture("basic");
  const bin = `${root}/bin`;
  await Deno.mkdir(bin);
  await Deno.symlink(await command(root, "which", "node"), `${bin}/node`);
  try {
    const { context, resources } = testContext(root, {
      environment: { PATH: bin },
    });
    await rejects(
      () => model.methods.inspect.execute({}, context),
      "Unable to determine npm version",
    );
    const invocation = resources.find((item) => item.specName === "invocation");
    assert(
      invocation?.data.executionStatus === "failed",
      "npm launch failure evidence missing",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("audit findings persist before policy failure", async () => {
  const root = await fixture("basic");
  const bin = `${root}/bin`;
  await Deno.mkdir(bin);
  await Deno.symlink(await command(root, "which", "node"), `${bin}/node`);
  const fakeNpm = `${bin}/npm`;
  await Deno.writeTextFile(
    fakeNpm,
    `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "--version") {
  console.log("11.19.0");
} else if (args[0] === "audit") {
  console.log(JSON.stringify({
    vulnerabilities: {
      example: {
        severity: "high",
        isDirect: true,
        range: "<2.0.0",
        via: ["Example advisory"],
        fixAvailable: true
      }
    },
    metadata: { vulnerabilities: { high: 1, total: 1 } }
  }));
  process.exitCode = 1;
} else {
  process.exitCode = 2;
}
`,
  );
  await Deno.chmod(fakeNpm, 0o755);
  try {
    const { context, resources, files } = testContext(root, {
      environment: { PATH: bin },
    });
    await rejects(
      () =>
        model.methods.audit.execute({
          ...workspaceDefaults,
          auditLevel: "low",
          omit: [],
          include: [],
          failOnFindings: true,
        }, context),
      "findings failed policy",
    );
    const report = resources.find((item) => item.specName === "auditReport");
    assert(
      report?.data.executionStatus === "succeeded",
      "Audit execution status missing",
    );
    assert(
      report.data.findingsStatus === "findings",
      "Audit findings status missing",
    );
    assert(
      report.data.policyStatus === "failed",
      "Audit policy status missing",
    );
    assert(
      files.some((item) => item.specName === "rawJson"),
      "Raw audit JSON missing",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

async function fileExists(path: string) {
  try {
    await Deno.stat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}
