/** Typed, reproducible npm project inspection and execution. @module */
import { z } from "npm:zod@4";
import { satisfies, valid } from "npm:semver@7.7.2";

const VERSION = "2026.08.26.1";
const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;

const ProjectArgumentsSchema = z.object({
  projectDir: z.string().default("."),
  expectedNpmVersion: z.string().optional(),
  expectedNodeVersion: z.string().optional(),
  strictToolchain: z.boolean().default(true),
  configPolicy: z.literal("project").default("project"),
  lifecycleScripts: z.enum(["deny", "allow"]).default("deny"),
  allowedScripts: z.array(z.string()).default([]),
  environment: z.record(z.string(), z.string()).meta({ sensitive: true })
    .default({}),
  defaultTimeoutMs: z.number().int().positive().default(900_000),
  requireCleanGit: z.boolean().default(false),
});

const WorkspaceSchema = z.object({
  workspaces: z.array(z.string()).default([]),
  includeWorkspaceRoot: z.boolean().default(false),
});

const ProjectSnapshotSchema = z.object({
  name: z.string().nullable(),
  private: z.boolean(),
  packageManager: z.string().nullable(),
  nodeEngine: z.string().nullable(),
  npmEngine: z.string().nullable(),
  nodeVersion: z.string(),
  npmVersion: z.string(),
  lockfilePath: z.string().nullable(),
  lockfileVersion: z.number().int().nullable(),
  workspaces: z.array(z.string()),
  scripts: z.array(z.string()),
  packageJsonSha256: z.string(),
  lockfileSha256: z.string().nullable(),
  npmrcSha256: z.string().nullable(),
  lifecyclePolicy: z.enum(["deny", "allow"]),
  inspectedAt: z.iso.datetime(),
  gitHead: z.string().nullable(),
});

const InvocationSchema = z.object({
  operation: z.enum(["inspect", "ci", "run", "list", "audit"]),
  argv: z.array(z.string()),
  projectDir: z.string(),
  startedAt: z.iso.datetime(),
  completedAt: z.iso.datetime(),
  durationMs: z.number().nonnegative(),
  exitCode: z.number().int().nullable(),
  executionStatus: z.enum(["succeeded", "failed"]),
  error: z.string().nullable(),
  npmVersion: z.string().nullable(),
  nodeVersion: z.string().nullable(),
  platform: z.string(),
  workspaces: z.array(z.string()),
  lifecyclePolicy: z.enum(["deny", "allow"]),
  environmentKeys: z.array(z.string()),
  expectedGitHead: z.string().nullable(),
  packageJsonSha256Before: z.string().nullable(),
  packageJsonSha256After: z.string().nullable(),
  lockfilePath: z.string().nullable(),
  lockfileSha256Before: z.string().nullable(),
  lockfileSha256After: z.string().nullable(),
  npmrcSha256: z.string().nullable(),
  gitHeadBefore: z.string().nullable(),
  gitHeadAfter: z.string().nullable(),
  cleanWorktreeBefore: z.boolean().nullable(),
  cleanWorktreeAfter: z.boolean().nullable(),
});

type DependencyNode = {
  name: string;
  version: string | null;
  resolved: string | null;
  extraneous: boolean;
  invalid: boolean;
  peerMissing: boolean;
  dependencies: DependencyNode[];
};

const DependencyNodeSchema: z.ZodType<DependencyNode> = z.lazy(() =>
  z.object({
    name: z.string(),
    version: z.string().nullable(),
    resolved: z.string().nullable(),
    extraneous: z.boolean(),
    invalid: z.boolean(),
    peerMissing: z.boolean(),
    dependencies: z.array(DependencyNodeSchema),
  })
);

const DependencyTreeSchema = z.object({
  name: z.string().nullable(),
  version: z.string().nullable(),
  problems: z.array(z.string()),
  dependencies: z.array(DependencyNodeSchema),
  recordedAt: z.iso.datetime(),
});

const AuditFindingSchema = z.object({
  name: z.string(),
  severity: z.enum(["info", "low", "moderate", "high", "critical"]),
  direct: z.boolean(),
  range: z.string(),
  via: z.array(z.string()),
  fixAvailable: z.boolean(),
});

const AuditReportSchema = z.object({
  executionStatus: z.enum(["succeeded", "failed"]),
  findingsStatus: z.enum(["clean", "findings"]),
  policyStatus: z.enum(["passed", "failed"]),
  auditLevel: z.enum(["info", "low", "moderate", "high", "critical"]),
  counts: z.record(z.string(), z.number().int().nonnegative()),
  findings: z.array(AuditFindingSchema),
  error: z.string().nullable(),
  recordedAt: z.iso.datetime(),
});

const InspectArgsSchema = z.object({
  expectedGitHead: z.string().regex(/^[0-9a-f]{40}$/).optional(),
});

const CiArgsSchema = WorkspaceSchema.extend({
  omit: z.array(z.enum(["dev", "optional", "peer", "prod"])).default([]),
  include: z.array(z.enum(["dev", "optional", "peer", "prod"])).default([]),
  installStrategy: z.enum(["hoisted", "nested", "shallow", "linked"])
    .optional(),
  strictPeerDeps: z.boolean().default(false),
  dryRun: z.boolean().default(false),
  expectedGitHead: z.string().regex(/^[0-9a-f]{40}$/).optional(),
});

const RunArgsSchema = WorkspaceSchema.extend({
  script: z.string().min(1),
  args: z.array(z.string()).default([]),
  ifPresent: z.boolean().default(false),
  expectedGitHead: z.string().regex(/^[0-9a-f]{40}$/).optional(),
});

const ListArgsSchema = WorkspaceSchema.extend({
  package: z.string().min(1).refine((value) => !value.startsWith("-"), {
    message: "package must not start with '-'",
  }).optional(),
  depth: z.number().int().nonnegative().optional(),
  all: z.boolean().default(false),
  expectedGitHead: z.string().regex(/^[0-9a-f]{40}$/).optional(),
});

const AuditArgsSchema = WorkspaceSchema.extend({
  auditLevel: z.enum(["info", "low", "moderate", "high", "critical"])
    .default("low"),
  omit: z.array(z.enum(["dev", "optional", "peer", "prod"])).default([]),
  include: z.array(z.enum(["dev", "optional", "peer", "prod"])).default([]),
  failOnFindings: z.boolean().default(true),
  expectedGitHead: z.string().regex(/^[0-9a-f]{40}$/).optional(),
});

type GlobalArgs = z.infer<typeof ProjectArgumentsSchema>;
type Handle = { name: string };
type FileWriter = {
  writeLine(line: string): Promise<void>;
  writeText(text: string): Promise<Handle>;
  finalize(): Promise<Handle>;
};
type Context = {
  signal: AbortSignal;
  repoDir: string;
  globalArgs: GlobalArgs;
  writeResource(
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ): Promise<Handle>;
  createFileWriter(
    specName: string,
    name: string,
    overrides?: { streaming?: boolean },
  ): FileWriter;
  logger: {
    info(message: string, properties?: Record<string, unknown>): void;
    error(message: string, properties?: Record<string, unknown>): void;
  };
};

type PackageJson = {
  name: string | null;
  private: boolean;
  packageManager: string | null;
  engines: { node?: string; npm?: string };
  scripts: Record<string, string>;
  workspaces: string[];
};

type ProjectState = {
  dir: string;
  relativeDir: string;
  packageJson: PackageJson;
  packageJsonHash: string;
  lockfilePath: string | null;
  lockfileHash: string | null;
  lockfileVersion: number | null;
  npmrcHash: string | null;
  npmrcSecrets: string[];
};

type GitState = { head: string; clean: boolean };
type ProcessResult = {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  launchError: string | null;
  captureTruncated: boolean;
};

type Evidence = z.infer<typeof InvocationSchema>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function redact(value: string, secrets: string[]): string {
  return secrets.reduce(
    (text, secret) => secret ? text.replaceAll(secret, "[REDACTED]") : text,
    value,
  );
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}

async function sha256(content: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    Uint8Array.from(content).buffer,
  );
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function hashFile(path: string): Promise<string> {
  return await sha256(await Deno.readFile(path));
}

function parsePackageJson(value: unknown): PackageJson {
  const parsed = z.object({
    name: z.string().optional(),
    private: z.boolean().optional(),
    packageManager: z.string().optional(),
    engines: z.object({
      node: z.string().optional(),
      npm: z.string().optional(),
    })
      .optional(),
    scripts: z.record(z.string(), z.string()).optional(),
    workspaces: z.union([
      z.array(z.string()),
      z.object({ packages: z.array(z.string()) }),
    ]).optional(),
  }).parse(value);
  return {
    name: parsed.name ?? null,
    private: parsed.private ?? false,
    packageManager: parsed.packageManager ?? null,
    engines: parsed.engines ?? {},
    scripts: parsed.scripts ?? {},
    workspaces: Array.isArray(parsed.workspaces)
      ? parsed.workspaces
      : parsed.workspaces?.packages ?? [],
  };
}

function npmrcSecrets(content: string): string[] {
  const secrets: string[] = [];
  for (const line of content.split("\n")) {
    const match = line.match(/^\s*([^#;][^=]*)=(.*)$/);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    const value = match[2].trim().replace(/^(?:"(.*)"|'(.*)')$/, "$1$2");
    if (
      /(?:_auth|token|password|secret)/.test(key) && value &&
      !value.startsWith("${")
    ) {
      secrets.push(value);
      continue;
    }
    try {
      const url = new URL(value);
      if (url.username) secrets.push(decodeURIComponent(url.username));
      if (url.password) secrets.push(decodeURIComponent(url.password));
    } catch {
      // Non-URL configuration is not secret unless its key says so.
    }
  }
  return secrets;
}

async function resolveProject(
  repoDir: string,
  projectDir: string,
): Promise<string> {
  if (/^(?:[a-zA-Z]:[\\/]|[\\/])/.test(projectDir)) {
    throw new Error("projectDir must be relative to the repository");
  }
  const root = await Deno.realPath(repoDir);
  const separator = Deno.build.os === "windows" ? "\\" : "/";
  const candidate = await Deno.realPath(`${root}${separator}${projectDir}`);
  const foldedRoot = Deno.build.os === "windows" ? root.toLowerCase() : root;
  const foldedCandidate = Deno.build.os === "windows"
    ? candidate.toLowerCase()
    : candidate;
  if (
    foldedCandidate !== foldedRoot &&
    !foldedCandidate.startsWith(`${foldedRoot}${separator}`)
  ) {
    throw new Error(`projectDir escapes the repository: ${projectDir}`);
  }
  return candidate;
}

async function readProject(
  repoDir: string,
  projectDir: string,
): Promise<ProjectState> {
  const root = await Deno.realPath(repoDir);
  const dir = await resolveProject(root, projectDir);
  const packagePath = `${dir}/package.json`;
  if (!(await exists(packagePath))) {
    throw new Error(`package.json not found in ${projectDir}`);
  }
  const packageBytes = await Deno.readFile(packagePath);
  const packageJson = parsePackageJson(
    JSON.parse(new TextDecoder().decode(packageBytes)),
  );
  const lockPath = `${dir}/package-lock.json`;
  const hasLock = await exists(lockPath);
  let lockfileVersion: number | null = null;
  if (hasLock) {
    const lock = z.object({ lockfileVersion: z.number().int() }).parse(
      JSON.parse(await Deno.readTextFile(lockPath)),
    );
    lockfileVersion = lock.lockfileVersion;
  }
  const npmrcPath = `${dir}/.npmrc`;
  const npmrc = await exists(npmrcPath)
    ? await Deno.readTextFile(npmrcPath)
    : null;
  return {
    dir,
    relativeDir: dir === root ? "." : dir.slice(root.length + 1),
    packageJson,
    packageJsonHash: await sha256(packageBytes),
    lockfilePath: hasLock ? "package-lock.json" : null,
    lockfileHash: hasLock ? await hashFile(lockPath) : null,
    lockfileVersion,
    npmrcHash: npmrc === null ? null : await hashFile(npmrcPath),
    npmrcSecrets: npmrc === null ? [] : npmrcSecrets(npmrc),
  };
}

function isolatedEnvironment(
  globalArgs: GlobalArgs,
  home: string,
  userConfig: string,
  globalConfig: string,
) {
  const inherited = Deno.env.toObject();
  const environment: Record<string, string> = {};
  for (
    const key of [
      "PATH",
      "Path",
      "SHELL",
      "SystemRoot",
      "WINDIR",
      "COMSPEC",
      "PATHEXT",
      "TMPDIR",
      "TMP",
      "TEMP",
    ]
  ) {
    if (inherited[key] !== undefined) environment[key] = inherited[key];
  }
  return {
    ...environment,
    HOME: home,
    USERPROFILE: home,
    NPM_CONFIG_USERCONFIG: userConfig,
    NPM_CONFIG_GLOBALCONFIG: globalConfig,
    ...globalArgs.environment,
  };
}

async function runProcess(
  command: string,
  args: string[],
  cwd: string,
  env: Record<string, string>,
  timeoutMs: number,
  parentSignal: AbortSignal,
  log: FileWriter,
  secrets: string[],
): Promise<ProcessResult> {
  const controller = new AbortController();
  let timedOut = false;
  const abort = () => controller.abort(parentSignal.reason);
  parentSignal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error(`Command timed out after ${timeoutMs}ms`));
  }, timeoutMs);
  let writeQueue = Promise.resolve();
  const writeLog = (stream: string, line: string) => {
    const safe = redact(line, secrets);
    writeQueue = writeQueue.then(() => log.writeLine(`[${stream}] ${safe}`));
  };
  const captured: Record<"stdout" | "stderr", Uint8Array[]> = {
    stdout: [],
    stderr: [],
  };
  let capturedBytes = 0;
  let captureTruncated = false;

  try {
    if (parentSignal.aborted) {
      const message = "Command cancelled before launch";
      writeLog("error", message);
      await writeQueue;
      return {
        code: -1,
        stdout: "",
        stderr: message,
        timedOut: false,
        launchError: message,
        captureTruncated: false,
      };
    }
    writeLog(
      "command",
      [command, ...args].map((item) => redact(item, secrets)).join(" "),
    );
    let child: Deno.ChildProcess;
    try {
      child = new Deno.Command(command, {
        args,
        cwd,
        env,
        clearEnv: true,
        signal: controller.signal,
        stdin: "null",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
    } catch (error) {
      const message = errorMessage(error);
      writeLog("error", message);
      await writeQueue;
      return {
        code: -1,
        stdout: "",
        stderr: message,
        timedOut,
        launchError: message,
        captureTruncated: false,
      };
    }

    const pump = async (
      stream: "stdout" | "stderr",
      source: ReadableStream<Uint8Array>,
    ) => {
      const reader = source.getReader();
      const decoder = new TextDecoder();
      let pending = "";
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (capturedBytes + value.length <= MAX_CAPTURE_BYTES) {
            captured[stream].push(value.slice());
            capturedBytes += value.length;
          } else {
            captureTruncated = true;
          }
          pending += decoder.decode(value, { stream: true });
          const lines = pending.split("\n");
          pending = lines.pop() ?? "";
          for (const line of lines) writeLog(stream, line.replace(/\r$/, ""));
          if (pending.length > 65_536) {
            writeLog(stream, `${pending.slice(0, 65_536)} [line continued]`);
            pending = pending.slice(65_536);
          }
        }
        pending += decoder.decode();
        if (pending) writeLog(stream, pending.replace(/\r$/, ""));
      } finally {
        reader.releaseLock();
      }
    };

    const statusPromise = child.status.then(
      (status) => ({ code: status.code, error: null as string | null }),
      (error) => ({ code: -1, error: errorMessage(error) }),
    );
    await Promise.allSettled([
      pump("stdout", child.stdout),
      pump("stderr", child.stderr),
    ]);
    const status = await statusPromise;
    if (status.error) writeLog("error", status.error);
    if (captureTruncated) {
      writeLog("error", `Output capture exceeded ${MAX_CAPTURE_BYTES} bytes`);
    }
    await writeQueue;
    const decode = (chunks: Uint8Array[]) => {
      const size = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
      const joined = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        joined.set(chunk, offset);
        offset += chunk.length;
      }
      return redact(new TextDecoder().decode(joined), secrets);
    };
    return {
      code: status.code,
      stdout: decode(captured.stdout),
      stderr: decode(captured.stderr),
      timedOut,
      launchError: status.error,
      captureTruncated,
    };
  } finally {
    clearTimeout(timer);
    parentSignal.removeEventListener("abort", abort);
  }
}

async function gitState(
  project: ProjectState,
  env: Record<string, string>,
  context: Context,
  log: FileWriter,
  secrets: string[],
): Promise<GitState | null> {
  const head = await runProcess(
    "git",
    ["rev-parse", "HEAD"],
    project.dir,
    env,
    context.globalArgs.defaultTimeoutMs,
    context.signal,
    log,
    secrets,
  );
  if (head.code !== 0) return null;
  const status = await runProcess(
    "git",
    ["status", "--porcelain", "--untracked-files=no"],
    project.dir,
    env,
    context.globalArgs.defaultTimeoutMs,
    context.signal,
    log,
    secrets,
  );
  if (status.code !== 0) return null;
  return { head: head.stdout.trim(), clean: status.stdout.trim() === "" };
}

function requireVersion(actual: string, expected: string, label: string) {
  const normalized = actual.replace(/^v/, "");
  if (!valid(normalized)) {
    throw new Error(`Invalid actual ${label} version: ${actual}`);
  }
  const exact = valid(expected);
  if (exact ? normalized !== exact : !satisfies(normalized, expected)) {
    throw new Error(`${label} ${normalized} does not satisfy ${expected}`);
  }
}

async function prepare(
  context: Context,
  log: FileWriter,
  expectedGitHead: string | undefined,
  requireLockfile: boolean,
) {
  const project = await readProject(
    context.repoDir,
    context.globalArgs.projectDir,
  );
  if (requireLockfile && !project.lockfilePath) {
    throw new Error("package-lock.json is required");
  }
  const configDir = await Deno.makeTempDir({ prefix: "swamp-npm-" });
  const userConfig = `${configDir}/user-npmrc`;
  const globalConfig = `${configDir}/global-npmrc`;
  try {
    await Promise.all([
      Deno.writeTextFile(userConfig, ""),
      Deno.writeTextFile(globalConfig, ""),
    ]);
    const env = isolatedEnvironment(
      context.globalArgs,
      configDir,
      userConfig,
      globalConfig,
    );
    const secrets = [
      ...Object.values(context.globalArgs.environment),
      ...project.npmrcSecrets,
    ].filter(Boolean);
    const node = await runProcess(
      "node",
      ["--version"],
      project.dir,
      env,
      context.globalArgs.defaultTimeoutMs,
      context.signal,
      log,
      secrets,
    );
    if (node.code !== 0) {
      throw new Error(
        `Unable to determine Node version: ${node.stderr.trim()}`,
      );
    }
    const npm = await runProcess(
      "npm",
      ["--version"],
      project.dir,
      env,
      context.globalArgs.defaultTimeoutMs,
      context.signal,
      log,
      secrets,
    );
    if (npm.code !== 0) {
      throw new Error(`Unable to determine npm version: ${npm.stderr.trim()}`);
    }
    const nodeVersion = node.stdout.trim().replace(/^v/, "");
    const npmVersion = npm.stdout.trim();
    const packageManagerMatch = project.packageJson.packageManager?.match(
      /^npm@([^+]+)(?:\+.*)?$/,
    );
    if (project.packageJson.packageManager && !packageManagerMatch) {
      throw new Error(
        `packageManager must identify npm, got ${project.packageJson.packageManager}`,
      );
    }
    const packageManagerVersion = packageManagerMatch?.[1];
    if (
      packageManagerVersion && context.globalArgs.expectedNpmVersion &&
      packageManagerVersion !== context.globalArgs.expectedNpmVersion
    ) {
      throw new Error(
        `packageManager npm@${packageManagerVersion} disagrees with expectedNpmVersion ${context.globalArgs.expectedNpmVersion}`,
      );
    }
    const expectedNpm = context.globalArgs.expectedNpmVersion ??
      packageManagerVersion;
    if (context.globalArgs.strictToolchain && !expectedNpm) {
      throw new Error(
        "strictToolchain requires packageManager npm@<version> or expectedNpmVersion",
      );
    }
    if (expectedNpm) requireVersion(npmVersion, expectedNpm, "npm");
    if (project.packageJson.engines.npm) {
      requireVersion(npmVersion, project.packageJson.engines.npm, "npm");
    }
    if (project.packageJson.engines.node) {
      requireVersion(nodeVersion, project.packageJson.engines.node, "Node");
    }
    if (context.globalArgs.expectedNodeVersion) {
      requireVersion(
        nodeVersion,
        context.globalArgs.expectedNodeVersion,
        "Node",
      );
    }
    const git = await gitState(project, env, context, log, secrets);
    if (expectedGitHead && git?.head !== expectedGitHead) {
      throw new Error(
        `Git head mismatch: expected ${expectedGitHead}, got ${
          git?.head ?? "no Git repository"
        }`,
      );
    }
    if (context.globalArgs.requireCleanGit && !git) {
      throw new Error("requireCleanGit requires a Git worktree");
    }
    if (context.globalArgs.requireCleanGit && git && !git.clean) {
      throw new Error(
        "Tracked Git worktree must be clean before npm execution",
      );
    }
    return {
      project,
      env,
      secrets,
      nodeVersion,
      npmVersion,
      git,
      configDir,
    };
  } catch (error) {
    await Deno.remove(configDir, { recursive: true }).catch(() => {});
    throw error;
  }
}

function workspaceArgv(args: z.infer<typeof WorkspaceSchema>): string[] {
  return [
    ...args.workspaces.flatMap((workspace) => ["--workspace", workspace]),
    ...(args.includeWorkspaceRoot ? ["--include-workspace-root"] : []),
  ];
}

function normalizeDependencies(value: unknown): DependencyNode[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a.localeCompare(b)
  ).map(([name, raw]) => {
    const item = raw && typeof raw === "object" && !Array.isArray(raw)
      ? raw as Record<string, unknown>
      : {};
    return {
      name,
      version: typeof item.version === "string" ? item.version : null,
      resolved: typeof item.resolved === "string" ? item.resolved : null,
      extraneous: item.extraneous === true,
      invalid: item.invalid === true,
      peerMissing: item.peerMissing === true,
      dependencies: normalizeDependencies(item.dependencies),
    };
  });
}

function normalizeAudit(value: unknown) {
  const root = value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
  const vulnerabilities = root.vulnerabilities &&
      typeof root.vulnerabilities === "object" &&
      !Array.isArray(root.vulnerabilities)
    ? root.vulnerabilities as Record<string, unknown>
    : {};
  const findings = Object.entries(vulnerabilities).sort(([a], [b]) =>
    a.localeCompare(b)
  ).map(([name, raw]) => {
    const finding = raw && typeof raw === "object" && !Array.isArray(raw)
      ? raw as Record<string, unknown>
      : {};
    const severity = z.enum(["info", "low", "moderate", "high", "critical"])
      .catch("info").parse(finding.severity);
    const via = Array.isArray(finding.via)
      ? finding.via.map((entry) =>
        typeof entry === "string"
          ? entry
          : entry && typeof entry === "object" && "title" in entry
          ? String(entry.title)
          : JSON.stringify(entry)
      )
      : [];
    return {
      name,
      severity,
      direct: finding.isDirect === true,
      range: typeof finding.range === "string" ? finding.range : "",
      via,
      fixAvailable: Boolean(finding.fixAvailable),
    };
  });
  const metadata = root.metadata && typeof root.metadata === "object"
    ? root.metadata as Record<string, unknown>
    : {};
  const rawCounts = metadata.vulnerabilities &&
      typeof metadata.vulnerabilities === "object"
    ? metadata.vulnerabilities as Record<string, unknown>
    : {};
  const counts = Object.fromEntries(
    Object.entries(rawCounts).filter((entry): entry is [string, number] =>
      typeof entry[1] === "number" && Number.isInteger(entry[1]) &&
      entry[1] >= 0
    ),
  );
  return { root, findings, counts };
}

async function executeWithEvidence(
  operation: Evidence["operation"],
  expectedGitHead: string | undefined,
  workspaces: string[],
  argv: string[],
  context: Context,
  body: (
    prepared: Awaited<ReturnType<typeof prepare>>,
    log: FileWriter,
    evidence: Evidence,
  ) => Promise<Handle[]>,
  requireLockfile = false,
): Promise<{ dataHandles: Handle[] }> {
  const started = Date.now();
  const suffix = `${started}-${crypto.randomUUID().slice(0, 8)}`;
  const log = context.createFileWriter("log", `log-${operation}-${suffix}`, {
    streaming: true,
  });
  const evidence: Evidence = {
    operation,
    argv: argv.map((item) =>
      redact(item, Object.values(context.globalArgs.environment))
    ),
    projectDir: context.globalArgs.projectDir,
    startedAt: new Date(started).toISOString(),
    completedAt: new Date(started).toISOString(),
    durationMs: 0,
    exitCode: null,
    executionStatus: "failed",
    error: null,
    npmVersion: null,
    nodeVersion: null,
    platform: `${Deno.build.os}-${Deno.build.arch}`,
    workspaces,
    lifecyclePolicy: context.globalArgs.lifecycleScripts,
    environmentKeys: Object.keys(context.globalArgs.environment).sort(),
    expectedGitHead: expectedGitHead ?? null,
    packageJsonSha256Before: null,
    packageJsonSha256After: null,
    lockfilePath: null,
    lockfileSha256Before: null,
    lockfileSha256After: null,
    npmrcSha256: null,
    gitHeadBefore: null,
    gitHeadAfter: null,
    cleanWorktreeBefore: null,
    cleanWorktreeAfter: null,
  };
  let prepared: Awaited<ReturnType<typeof prepare>> | null = null;
  let logHandle: Handle | null = null;
  try {
    context.logger.info("Starting npm {operation}", { operation });
    prepared = await prepare(context, log, expectedGitHead, requireLockfile);
    evidence.projectDir = prepared.project.relativeDir;
    evidence.npmVersion = prepared.npmVersion;
    evidence.nodeVersion = prepared.nodeVersion;
    evidence.packageJsonSha256Before = prepared.project.packageJsonHash;
    evidence.lockfilePath = prepared.project.lockfilePath;
    evidence.lockfileSha256Before = prepared.project.lockfileHash;
    evidence.npmrcSha256 = prepared.project.npmrcHash;
    evidence.gitHeadBefore = prepared.git?.head ?? null;
    evidence.cleanWorktreeBefore = prepared.git?.clean ?? null;
    const secrets = prepared.secrets;
    evidence.argv = argv.map((item) => redact(item, secrets));
    const handles = await body(prepared, log, evidence);
    const after = await readProject(
      context.repoDir,
      context.globalArgs.projectDir,
    );
    const gitAfter = await gitState(
      after,
      prepared.env,
      context,
      log,
      prepared.secrets,
    );
    evidence.packageJsonSha256After = after.packageJsonHash;
    evidence.lockfileSha256After = after.lockfileHash;
    evidence.gitHeadAfter = gitAfter?.head ?? null;
    evidence.cleanWorktreeAfter = gitAfter?.clean ?? null;
    if (
      operation === "ci" &&
      after.packageJsonHash !== prepared.project.packageJsonHash
    ) {
      throw new Error("npm ci changed package.json");
    }
    if (
      operation === "ci" && after.lockfileHash !== prepared.project.lockfileHash
    ) {
      throw new Error("npm ci changed package-lock.json");
    }
    if (prepared.git && !gitAfter) {
      throw new Error("Unable to inspect Git state after npm execution");
    }
    if (prepared.git?.head !== gitAfter?.head) {
      throw new Error("Git head changed during npm execution");
    }
    if (context.globalArgs.requireCleanGit && !gitAfter?.clean) {
      throw new Error("Tracked Git worktree changed during npm execution");
    }
    evidence.executionStatus = "succeeded";
    evidence.completedAt = new Date().toISOString();
    evidence.durationMs = Date.now() - started;
    logHandle = await log.finalize();
    const invocation = await context.writeResource(
      "invocation",
      `invocation-${operation}-${suffix}`,
      evidence,
    );
    context.logger.info("Completed npm {operation}", { operation });
    return { dataHandles: [...handles, invocation, logHandle] };
  } catch (error) {
    const message = redact(
      errorMessage(error),
      prepared?.secrets ?? Object.values(context.globalArgs.environment),
    );
    context.logger.error("npm {operation} failed: {error}", {
      operation,
      error: message,
    });
    evidence.error = message;
    evidence.completedAt = new Date().toISOString();
    evidence.durationMs = Date.now() - started;
    if (prepared) {
      evidence.npmVersion = prepared.npmVersion;
      evidence.nodeVersion = prepared.nodeVersion;
      evidence.packageJsonSha256Before = prepared.project.packageJsonHash;
      evidence.lockfilePath = prepared.project.lockfilePath;
      evidence.lockfileSha256Before = prepared.project.lockfileHash;
      evidence.npmrcSha256 = prepared.project.npmrcHash;
      evidence.gitHeadBefore = prepared.git?.head ?? null;
      evidence.cleanWorktreeBefore = prepared.git?.clean ?? null;
      try {
        const after = await readProject(
          context.repoDir,
          context.globalArgs.projectDir,
        );
        const gitAfter = await gitState(
          after,
          prepared.env,
          context,
          log,
          prepared.secrets,
        );
        evidence.packageJsonSha256After = after.packageJsonHash;
        evidence.lockfileSha256After = after.lockfileHash;
        evidence.gitHeadAfter = gitAfter?.head ?? null;
        evidence.cleanWorktreeAfter = gitAfter?.clean ?? null;
      } catch {
        // The original error remains authoritative; partial after-state is nullable.
      }
    }
    try {
      await log.writeLine(`[error] ${message}`);
      logHandle ??= await log.finalize();
    } catch {
      // Preserve the original execution error when log finalization also fails.
    }
    await context.writeResource(
      "invocation",
      `invocation-${operation}-${suffix}`,
      evidence,
    );
    throw new Error(message);
  } finally {
    if (prepared?.configDir) {
      await Deno.remove(prepared.configDir, { recursive: true }).catch(
        () => {},
      );
    }
  }
}

/** npm project model. */
export const model = {
  type: "@funsaized/npm/project",
  version: VERSION,
  globalArguments: ProjectArgumentsSchema,
  resources: {
    project: {
      description: "Inspected npm project metadata and toolchain identity",
      schema: ProjectSnapshotSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    invocation: {
      description: "Success or durable failure evidence for one operation",
      schema: InvocationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 500,
    },
    dependencyTree: {
      description: "Normalized npm dependency tree",
      schema: DependencyTreeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    auditReport: {
      description:
        "Normalized npm audit execution, findings, and policy result",
      schema: AuditReportSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
  },
  files: {
    log: {
      description: "Redacted streaming command log",
      contentType: "text/plain",
      streaming: true,
      lifetime: "infinite" as const,
      garbageCollection: 200,
    },
    rawJson: {
      description: "Redacted raw npm JSON output",
      contentType: "application/json",
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
  },
  checks: {},
  methods: {
    inspect: {
      description:
        "Inspect npm manifests, configuration hashes, Git state, and toolchain",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: Context,
      ) =>
        await executeWithEvidence(
          "inspect",
          args.expectedGitHead,
          [],
          ["node", "--version", "npm", "--version"],
          context,
          async (prepared) => {
            const snapshot = await context.writeResource(
              "project",
              "project-current",
              {
                name: prepared.project.packageJson.name,
                private: prepared.project.packageJson.private,
                packageManager: prepared.project.packageJson.packageManager,
                nodeEngine: prepared.project.packageJson.engines.node ?? null,
                npmEngine: prepared.project.packageJson.engines.npm ?? null,
                nodeVersion: prepared.nodeVersion,
                npmVersion: prepared.npmVersion,
                lockfilePath: prepared.project.lockfilePath,
                lockfileVersion: prepared.project.lockfileVersion,
                workspaces: prepared.project.packageJson.workspaces,
                scripts: Object.keys(prepared.project.packageJson.scripts)
                  .sort(),
                packageJsonSha256: prepared.project.packageJsonHash,
                lockfileSha256: prepared.project.lockfileHash,
                npmrcSha256: prepared.project.npmrcHash,
                lifecyclePolicy: context.globalArgs.lifecycleScripts,
                inspectedAt: new Date().toISOString(),
                gitHead: prepared.git?.head ?? null,
              },
            );
            return [snapshot];
          },
        ),
    },
    ci: {
      description:
        "Run reproducible npm ci with lifecycle scripts denied by default",
      arguments: CiArgsSchema,
      execute: async (args: z.infer<typeof CiArgsSchema>, context: Context) => {
        const argv = [
          "ci",
          ...(context.globalArgs.lifecycleScripts === "deny"
            ? ["--ignore-scripts"]
            : []),
          "--no-audit",
          "--no-fund",
          ...args.omit.map((value) => `--omit=${value}`),
          ...args.include.map((value) => `--include=${value}`),
          ...(args.installStrategy
            ? [`--install-strategy=${args.installStrategy}`]
            : []),
          ...(args.strictPeerDeps ? ["--strict-peer-deps"] : []),
          ...(args.dryRun ? ["--dry-run"] : []),
          ...workspaceArgv(args),
        ];
        return await executeWithEvidence(
          "ci",
          args.expectedGitHead,
          args.workspaces,
          ["npm", ...argv],
          context,
          async (prepared, log, evidence) => {
            const result = await runProcess(
              "npm",
              argv,
              prepared.project.dir,
              prepared.env,
              context.globalArgs.defaultTimeoutMs,
              context.signal,
              log,
              prepared.secrets,
            );
            evidence.exitCode = result.code;
            if (result.timedOut) throw new Error("npm ci timed out");
            if (result.captureTruncated) {
              throw new Error("npm ci output exceeded capture limit");
            }
            if (result.code !== 0) {
              throw new Error(
                result.launchError || result.stderr.trim() ||
                  `npm ci exited ${result.code}`,
              );
            }
            return [];
          },
          true,
        );
      },
    },
    run: {
      description:
        "Run an existing, explicitly allowed package script without a shell",
      arguments: RunArgsSchema,
      execute: async (
        args: z.infer<typeof RunArgsSchema>,
        context: Context,
      ) => {
        const argv = [
          "run",
          args.script,
          ...(args.ifPresent ? ["--if-present"] : []),
          ...workspaceArgv(args),
          ...(args.args.length ? ["--", ...args.args] : []),
        ];
        return await executeWithEvidence(
          "run",
          args.expectedGitHead,
          args.workspaces,
          ["npm", ...argv],
          context,
          async (prepared, log, evidence) => {
            if (
              context.globalArgs.allowedScripts.length > 0 &&
              !context.globalArgs.allowedScripts.includes(args.script)
            ) {
              throw new Error(`Script is not allowed: ${args.script}`);
            }
            if (
              args.workspaces.length === 0 &&
              !prepared.project.packageJson.scripts[args.script] &&
              !args.ifPresent
            ) {
              throw new Error(`Unknown package script: ${args.script}`);
            }
            const result = await runProcess(
              "npm",
              argv,
              prepared.project.dir,
              prepared.env,
              context.globalArgs.defaultTimeoutMs,
              context.signal,
              log,
              prepared.secrets,
            );
            evidence.exitCode = result.code;
            if (result.timedOut) {
              throw new Error(`npm run ${args.script} timed out`);
            }
            if (result.captureTruncated) {
              throw new Error("npm run output exceeded capture limit");
            }
            if (result.code !== 0) {
              throw new Error(
                result.launchError || result.stderr.trim() ||
                  `npm run exited ${result.code}`,
              );
            }
            return [];
          },
        );
      },
    },
    list: {
      description: "Record raw and normalized npm ls JSON output",
      arguments: ListArgsSchema,
      execute: async (
        args: z.infer<typeof ListArgsSchema>,
        context: Context,
      ) => {
        const argv = [
          "ls",
          ...(args.package ? [args.package] : []),
          "--json",
          ...(args.depth !== undefined ? [`--depth=${args.depth}`] : []),
          ...(args.all ? ["--all"] : []),
          ...workspaceArgv(args),
        ];
        return await executeWithEvidence(
          "list",
          args.expectedGitHead,
          args.workspaces,
          ["npm", ...argv],
          context,
          async (prepared, log, evidence) => {
            const result = await runProcess(
              "npm",
              argv,
              prepared.project.dir,
              prepared.env,
              context.globalArgs.defaultTimeoutMs,
              context.signal,
              log,
              prepared.secrets,
            );
            evidence.exitCode = result.code;
            if (result.timedOut) throw new Error("npm ls timed out");
            if (result.captureTruncated) {
              throw new Error("npm ls JSON exceeded capture limit");
            }
            const raw = context.createFileWriter(
              "rawJson",
              `raw-list-${Date.now()}`,
            );
            const rawHandle = await raw.writeText(
              result.stdout || result.stderr,
            );
            let parsed: Record<string, unknown>;
            try {
              parsed = JSON.parse(result.stdout);
            } catch {
              throw new Error(
                result.launchError ?? "npm ls did not return valid JSON",
              );
            }
            const tree = await context.writeResource(
              "dependencyTree",
              `dependency-tree-${Date.now()}`,
              {
                name: typeof parsed.name === "string" ? parsed.name : null,
                version: typeof parsed.version === "string"
                  ? parsed.version
                  : null,
                problems: Array.isArray(parsed.problems)
                  ? parsed.problems.map(String)
                  : [],
                dependencies: normalizeDependencies(parsed.dependencies),
                recordedAt: new Date().toISOString(),
              },
            );
            if (result.code !== 0) {
              throw new Error(`npm ls exited ${result.code}`);
            }
            return [tree, rawHandle];
          },
        );
      },
    },
    audit: {
      description:
        "Record npm audit JSON before independently applying findings policy",
      arguments: AuditArgsSchema,
      execute: async (
        args: z.infer<typeof AuditArgsSchema>,
        context: Context,
      ) => {
        const argv = [
          "audit",
          "--json",
          `--audit-level=${args.auditLevel}`,
          ...args.omit.map((value) => `--omit=${value}`),
          ...args.include.map((value) => `--include=${value}`),
          ...workspaceArgv(args),
        ];
        return await executeWithEvidence(
          "audit",
          args.expectedGitHead,
          args.workspaces,
          ["npm", ...argv],
          context,
          async (prepared, log, evidence) => {
            const result = await runProcess(
              "npm",
              argv,
              prepared.project.dir,
              prepared.env,
              context.globalArgs.defaultTimeoutMs,
              context.signal,
              log,
              prepared.secrets,
            );
            evidence.exitCode = result.code;
            if (result.timedOut) throw new Error("npm audit timed out");
            if (result.captureTruncated) {
              throw new Error("npm audit JSON exceeded capture limit");
            }
            const raw = context.createFileWriter(
              "rawJson",
              `raw-audit-${Date.now()}`,
            );
            const rawHandle = await raw.writeText(
              result.stdout || result.stderr,
            );
            let parsed: unknown;
            try {
              parsed = JSON.parse(result.stdout);
            } catch {
              const report = await context.writeResource(
                "auditReport",
                `audit-report-${Date.now()}`,
                {
                  executionStatus: "failed",
                  findingsStatus: "clean",
                  policyStatus: "failed",
                  auditLevel: args.auditLevel,
                  counts: {},
                  findings: [],
                  error: result.launchError ??
                    "npm audit did not return valid JSON",
                  recordedAt: new Date().toISOString(),
                },
              );
              evidence.exitCode = result.code;
              void report;
              void rawHandle;
              throw new Error(
                result.launchError ?? "npm audit did not return valid JSON",
              );
            }
            const normalized = normalizeAudit(parsed);
            const executionFailed = Boolean(normalized.root.error) ||
              result.code > 1 || result.code < 0;
            const findings = normalized.findings.length > 0;
            const severity = ["info", "low", "moderate", "high", "critical"];
            const policyFindings = normalized.findings.some((finding) =>
              severity.indexOf(finding.severity) >=
                severity.indexOf(args.auditLevel)
            );
            const policyFailed = executionFailed ||
              (args.failOnFindings && policyFindings);
            const report = await context.writeResource(
              "auditReport",
              `audit-report-${Date.now()}`,
              {
                executionStatus: executionFailed ? "failed" : "succeeded",
                findingsStatus: findings ? "findings" : "clean",
                policyStatus: policyFailed ? "failed" : "passed",
                auditLevel: args.auditLevel,
                counts: normalized.counts,
                findings: normalized.findings,
                error: executionFailed
                  ? (typeof normalized.root.error === "object"
                    ? JSON.stringify(normalized.root.error)
                    : String(normalized.root.error ?? result.stderr.trim()))
                  : null,
                recordedAt: new Date().toISOString(),
              },
            );
            if (executionFailed) throw new Error("npm audit execution failed");
            if (policyFailed) {
              throw new Error("npm audit findings failed policy");
            }
            return [report, rawHandle];
          },
          true,
        );
      },
    },
  },
};

/** Narrow test surface for security and normalization contracts. */
export const testing = {
  normalizeAudit,
  normalizeDependencies,
  parsePackageJson,
  redact,
  resolveProject,
};
