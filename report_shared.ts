type Handle = {
  specName: string;
  name: string;
  version?: number;
  attributes?: Record<string, unknown>;
};

export type ReportContext = {
  modelType: unknown;
  modelId: string;
  methodName: string;
  executionStatus: "succeeded" | "failed";
  errorMessage?: string;
  dataHandles: Handle[];
  dataRepository: {
    getContent(
      type: unknown,
      modelId: string,
      name: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
};

export async function readResource(
  context: ReportContext,
  specName: string,
): Promise<Record<string, unknown> | null> {
  const handle = context.dataHandles.find((item) => item.specName === specName);
  if (!handle) return null;
  if (handle.attributes) return handle.attributes;
  const content = await context.dataRepository.getContent(
    context.modelType,
    context.modelId,
    handle.name,
    handle.version,
  );
  if (!content) return null;
  try {
    return JSON.parse(
      new TextDecoder().decode(content),
    ) as Record<string, unknown>;
  } catch {
    return null;
  }
}
