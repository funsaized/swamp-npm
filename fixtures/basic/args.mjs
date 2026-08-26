import { writeFile } from "node:fs/promises";

await writeFile("args.json", JSON.stringify(process.argv.slice(2)));
