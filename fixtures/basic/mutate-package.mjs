import { appendFile } from "node:fs/promises";

await appendFile("package.json", "\n");
