import { report } from "./sbom_summary.ts";

Deno.test("SBOM report counts declared licenses", async () => {
  const result = await report.execute({
    modelType: "@funsaized/npm/project",
    modelId: "model-id",
    methodName: "sbom",
    executionStatus: "succeeded",
    dataHandles: [{
      specName: "sbom",
      name: "sbom",
      attributes: {
        format: "cyclonedx",
        specVersion: "1.5",
        componentCount: 2,
        dependencyCount: 1,
        truncated: false,
        policyStatus: "passed",
        missingRequiredFields: [],
        components: [{ licenses: ["MIT"] }, { licenses: ["MIT"] }],
      },
    }],
    dataRepository: { getContent: () => Promise.resolve(null) },
  });
  if (!("licenseCounts" in result.json)) {
    throw new Error("license counts missing");
  }
  const counts = result.json.licenseCounts as Record<string, number>;
  if (counts.MIT !== 2) throw new Error("license count missing");
});
