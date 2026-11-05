import type { ModelDefinition } from "jsr:@swamp-club/swamp-testing@0.20261027.65";
import { model } from "./project.ts";
import { report as invocation } from "./invocation.ts";
import { report as auditFindings } from "./audit_findings.ts";
import { report as sbomSummary } from "./sbom_summary.ts";

// Check the public Swamp contract during `deno check` / `deno test`: method
// scoping belongs in definition YAML, not in the model type's report names.
const reportDefaults: Pick<ModelDefinition, "reports"> = model;

Deno.test("model report defaults resolve to the bundled method reports", () => {
  const reports = [invocation, auditFindings, sbomSummary];
  if (
    JSON.stringify(reportDefaults.reports) !==
      JSON.stringify(reports.map((report) => report.name))
  ) {
    throw new Error("Model report defaults must name the bundled reports");
  }
  if (reports.some((report) => report.scope !== "method")) {
    throw new Error("Model report defaults must support method execution");
  }
});

for (
  const { report, methodName, specName } of [
    { report: auditFindings, methodName: "audit", specName: "auditReport" },
    { report: sbomSummary, methodName: "sbom", specName: "sbom" },
  ]
) {
  Deno.test(`${report.name} ignores unrelated methods and their data`, async () => {
    for (const otherMethod of Object.keys(model.methods)) {
      if (otherMethod === methodName) continue;
      for (const executionStatus of ["succeeded", "failed"] as const) {
        const result = await report.execute({
          modelType: model.type,
          modelId: "model-id",
          methodName: otherMethod,
          executionStatus,
          // Even a matching handle from an unrelated run must not be read.
          dataHandles: [{ specName, name: "unrelated-data", version: 1 }],
          dataRepository: {
            getContent: () => {
              throw new Error("An unrelated method must not read report data");
            },
          },
        });
        if (result.json.applicable !== false) {
          throw new Error(`${report.name} must not apply to ${otherMethod}`);
        }
      }
    }
  });

  Deno.test(`${report.name} handles a failure before normalized data is written`, async () => {
    const result = await report.execute({
      modelType: model.type,
      modelId: "model-id",
      methodName,
      executionStatus: "failed",
      errorMessage: "Toolchain validation failed",
      dataHandles: [],
      dataRepository: {
        getContent: () => {
          throw new Error("Missing handles must not trigger a data lookup");
        },
      },
    });
    if (result.json.applicable !== true || result.json.available !== false) {
      throw new Error(
        "The report must distinguish missing data from clean data",
      );
    }
  });
}
