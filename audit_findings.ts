import { readResource, type ReportContext } from "./report_shared.ts";

/** Summarizes npm audit findings separately from command execution status. */
export const report = {
  name: "@funsaized/npm/audit-findings",
  description: "Summarize normalized npm audit findings and policy outcome",
  scope: "method" as const,
  labels: ["npm", "security", "audit"],
  execute: async (context: ReportContext) => {
    if (context.methodName !== "audit") {
      return {
        markdown: "# npm Audit\n\nNot an audit execution.\n",
        json: { applicable: false },
      };
    }
    const audit = await readResource(context, "auditReport");
    if (!audit) {
      return {
        markdown: "# npm Audit\n\nNo normalized audit report was produced.\n",
        json: { applicable: true, available: false },
      };
    }
    const findings = Array.isArray(audit.findings) ? audit.findings : [];
    const rows = findings.map((finding) => {
      const item = finding as Record<string, unknown>;
      const name = String(item.name).replaceAll("|", "\\|").replaceAll(
        "\n",
        " ",
      );
      return `| ${name} | ${item.severity} | ${item.direct} |`;
    }).join("\n");
    return {
      markdown: `# npm Audit

- Execution: **${audit.executionStatus}**
- Findings: **${audit.findingsStatus}**
- Policy: **${audit.policyStatus}**

| Package | Severity | Direct |
| --- | --- | --- |
${rows || "| _none_ | - | - |"}
`,
      json: { applicable: true, available: true, ...audit },
    };
  },
};
