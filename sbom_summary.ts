import { readResource, type ReportContext } from "./report_shared.ts";

/** Summarizes SBOM completeness and license declarations. */
export const report = {
  name: "@funsaized/npm/sbom-summary",
  description: "Summarize npm SBOM package, license, and completeness evidence",
  scope: "method" as const,
  labels: ["npm", "sbom", "supply-chain"],
  execute: async (context: ReportContext) => {
    if (context.methodName !== "sbom") {
      return {
        markdown: "# npm SBOM\n\nNot an SBOM execution.\n",
        json: { applicable: false },
      };
    }
    const sbom = await readResource(context, "sbom");
    if (!sbom) {
      return {
        markdown: "# npm SBOM\n\nNo normalized SBOM was produced.\n",
        json: { applicable: true, available: false },
      };
    }
    const components = Array.isArray(sbom.components) ? sbom.components : [];
    const licenses = components.flatMap((component) => {
      const values = (component as Record<string, unknown>).licenses;
      return Array.isArray(values) ? values.map(String) : [];
    });
    const licenseCounts = Object.fromEntries(
      [...new Set(licenses)].sort().map((license) => [
        license,
        licenses.filter((value) => value === license).length,
      ]),
    );
    const json = {
      applicable: true,
      available: true,
      format: sbom.format,
      specVersion: sbom.specVersion,
      componentCount: sbom.componentCount,
      dependencyCount: sbom.dependencyCount,
      truncated: sbom.truncated,
      policyStatus: sbom.policyStatus,
      missingRequiredFields: sbom.missingRequiredFields,
      licenseCounts,
    };
    return {
      markdown: `# npm SBOM

- Format: **${json.format} ${json.specVersion ?? ""}**
- Components: **${json.componentCount}**
- Dependencies: **${json.dependencyCount}**
- Policy: **${json.policyStatus}**
- Truncated: **${json.truncated}**

## Licenses

${
        Object.entries(licenseCounts).map(([license, count]) =>
          `- ${license}: ${count}`
        ).join("\n") || "No licenses declared."
      }
`,
      json,
    };
  },
};
