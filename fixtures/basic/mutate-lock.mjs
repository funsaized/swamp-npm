import { appendFile } from "node:fs/promises";

await appendFile("package-lock.json", "\n");
