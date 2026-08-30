import { report } from "./audit_findings.ts";

Deno.test("audit report renders normalized findings", async () => {
  const result = await report.execute({
    modelType: "@funsaized/npm/project",
    modelId: "model-id",
    methodName: "audit",
    executionStatus: "failed",
    dataHandles: [{
      specName: "auditReport",
      name: "audit-report",
      attributes: {
        executionStatus: "succeeded",
        findingsStatus: "findings",
        policyStatus: "failed",
        findings: [{ name: "unsafe|package", severity: "high", direct: true }],
      },
    }],
    dataRepository: { getContent: () => Promise.resolve(null) },
  });
  if (!result.markdown.includes("unsafe\\|package")) {
    throw new Error("finding was not safely rendered");
  }
});
