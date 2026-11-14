# @platform/api-client

Typed API client for the AI Platform backend.

## Regeneration

To regenerate the TypeScript types from the FastAPI OpenAPI schema:

```bash
# From workspace root:
pnpm generate:api
```

This runs:
1. `uv run python -m app.utils.export_openapi` to generate `apps/api/openapi.json`
2. `openapi-typescript` to update `packages/api-client/src/generated/schema.ts`

## Usage

```typescript
import { createApiClient } from "@platform/api-client";

const client = createApiClient({
  baseUrl: process.env.NEXT_PUBLIC_API_URL,
  getToken: async () => {
    // Return token from Clerk auth hook (e.g. getToken())
    return "session-token";
  },
});

// Check health
const health = await client.health.check();

// Get authenticated user
const me = await client.auth.me();
```
