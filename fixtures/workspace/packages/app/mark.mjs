import { writeFile } from "node:fs/promises";

await writeFile("workspace.marker", "workspace\n");
