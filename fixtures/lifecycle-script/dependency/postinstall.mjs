import { writeFile } from "node:fs/promises";

await writeFile(new URL("../postinstall.marker", import.meta.url), "ran\n");
