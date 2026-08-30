import { report } from "./invocation.ts";

Deno.test("invocation report summarizes execution evidence", async () => {
  const result = await report.execute({
    modelType: "@funsaized/npm/project",
    modelId: "model-id",
    methodName: "ci",
    executionStatus: "succeeded",
    dataHandles: [{
      specName: "invocation",
      name: "invocation-ci",
      attributes: {
        operation: "ci",
        executionStatus: "succeeded",
        exitCode: 0,
        durationMs: 10,
      },
    }],
    dataRepository: { getContent: () => Promise.resolve(null) },
  });
  if (!("operation" in result.json) || result.json.operation !== "ci") {
    throw new Error("operation missing");
  }
});
