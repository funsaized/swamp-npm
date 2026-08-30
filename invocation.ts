import { readResource, type ReportContext } from "./report_shared.ts";

/** Summarizes the durable execution evidence written by every npm method. */
export const report = {
  name: "@funsaized/npm/invocation",
  description: "Summarize npm invocation identity, outcome, and input hashes",
  scope: "method" as const,
  labels: ["npm", "evidence", "supply-chain"],
  execute: async (context: ReportContext) => {
    const invocation = await readResource(context, "invocation");
    if (!invocation) {
      return {
        markdown: "# npm Invocation\n\nNo invocation evidence was produced.\n",
        json: { available: false, method: context.methodName },
      };
    }
    const json = {
      available: true,
      operation: invocation.operation,
      executionStatus: invocation.executionStatus,
      exitCode: invocation.exitCode,
      durationMs: invocation.durationMs,
      gitHead: invocation.gitHeadBefore,
      packageJsonSha256: invocation.packageJsonSha256Before,
      lockfileSha256: invocation.lockfileSha256Before,
      npmVersion: invocation.npmVersion,
      nodeVersion: invocation.nodeVersion,
    };
    return {
      markdown: `# npm Invocation

| Field | Value |
| --- | --- |
| Operation | ${json.operation} |
| Status | ${json.executionStatus} |
| Exit code | ${json.exitCode ?? "n/a"} |
| Duration | ${json.durationMs} ms |
| Git head | ${json.gitHead ?? "n/a"} |
| package.json SHA-256 | ${json.packageJsonSha256 ?? "n/a"} |
| package-lock.json SHA-256 | ${json.lockfileSha256 ?? "n/a"} |
| Node / npm | ${json.nodeVersion ?? "n/a"} / ${json.npmVersion ?? "n/a"} |
`,
      json,
    };
  },
};
