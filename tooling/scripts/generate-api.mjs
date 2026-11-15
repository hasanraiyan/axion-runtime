import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "../..");

const apiDir = path.join(rootDir, "apps/api");
const openapiJsonPath = path.join(apiDir, "openapi.json");
const generatedOutputDir = path.join(rootDir, "packages/api-client/src/generated");
const generatedSchemaPath = path.join(generatedOutputDir, "schema.ts");

console.log("⚡ [generate:api] Exporting OpenAPI schema from FastAPI backend...");

try {
  // Run python script inside apps/api using uv
  execSync("uv run python -m app.utils.export_openapi", {
    cwd: apiDir,
    stdio: "inherit",
    env: {
      ...process.env,
      EXPORT_PATH: openapiJsonPath,
    },
  });

  if (!fs.existsSync(openapiJsonPath)) {
    throw new Error(`OpenAPI export file not found at: ${openapiJsonPath}`);
  }

  if (!fs.existsSync(generatedOutputDir)) {
    fs.mkdirSync(generatedOutputDir, { recursive: true });
  }

  console.log("⚡ [generate:api] Generating TypeScript types from OpenAPI schema...");
  execSync(
    `pnpm --filter @platform/api-client exec openapi-typescript "${openapiJsonPath}" -o "${generatedSchemaPath}"`,
    {
      cwd: rootDir,
      stdio: "inherit",
    }
  );

  console.log(`✅ [generate:api] Successfully generated schema at: ${generatedSchemaPath}`);

  console.log("⚡ [generate:api] Refreshing docs/api-routes.md...");
  execSync("node tooling/scripts/generate-routes-md.mjs", {
    cwd: rootDir,
    stdio: "inherit",
  });
} catch (error) {
  console.error("❌ [generate:api] Failed to generate API types:", error.message);
  process.exit(1);
}
