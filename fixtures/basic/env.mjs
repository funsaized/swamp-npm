import { writeFile } from "node:fs/promises";

await writeFile("env.json", JSON.stringify({
  inherited: process.env.NPM_CONFIG_REGISTRY ?? null,
  ambientSecret: process.env.GITHUB_TOKEN ?? null,
  explicit: process.env.EXPLICIT_TEST_VALUE ?? null,
}));
