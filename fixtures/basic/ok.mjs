import { writeFile } from "node:fs/promises";

await writeFile("ok.marker", "ok\n");
