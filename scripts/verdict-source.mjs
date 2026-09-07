import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const runsDir = resolve(process.env.VERDICT_RUNS_DIR || "runs");

export function sourcePath(relativePath) {
  if (!process.env.VERDICT_SOURCE_DIR) {
    throw new Error("Set VERDICT_SOURCE_DIR to a built VERDICT source checkout (see scripts/README.md).");
  }
  return resolve(process.env.VERDICT_SOURCE_DIR, relativePath);
}

export async function loadCore() {
  return import(pathToFileURL(sourcePath("packages/core/dist/index.js")).href);
}
