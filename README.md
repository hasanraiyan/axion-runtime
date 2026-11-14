# AI Platform Monorepo Foundation

Enterprise monorepo foundation for the AI Platform using Turborepo, Next.js, and FastAPI.

## Tech Stack

| Layer | Technology |
|---|---|
| Monorepo Orchestration | [Turborepo](https://turbo.build/) |
| JS Package Manager | [pnpm](https://pnpm.io/) |
| Frontend | [Next.js](https://nextjs.org/) (App Router, TypeScript, Tailwind CSS) |
| Backend | [FastAPI](https://fastapi.tiangolo.com/) (Python 3.13) |
| Python Package Manager | [uv](https://docs.astral.sh/uv/) |
| Authentication | [Clerk](https://clerk.com/) (`@clerk/nextjs` & `clerk-backend-api`) |
| API Specification | OpenAPI 3.1 & Swagger UI |
| SDK Generation | `openapi-typescript` |

---

## Workspace Structure

```text
├── apps/
│   ├── api/                    # FastAPI backend
│   │   ├── app/
│   │   │   ├── api/deps.py     # Auth & query dependencies
│   │   │   ├── api/v1/         # Versioned endpoints (/health, /auth/me)
│   │   │   ├── core/           # Config, exceptions, logging, security
│   │   │   ├── middleware/     # Request ID, Rate limit, Security headers, Access logs
│   │   │   ├── schemas/        # Generic ApiResponse[T], Pagination, Auth schemas
│   │   │   ├── utils/          # Pagination, Filtering, OpenAPI exporter
│   │   │   └── main.py         # App factory, CORS, exception handlers
│   │   ├── tests/              # Pytest test suite (11 passing tests)
│   │   ├── pyproject.toml      # UV dependency configuration
│   │   └── .env.example
│   │
│   └── web/                    # Next.js frontend
│       ├── app/
│       │   ├── layout.tsx      # ClerkProvider root wrapper
│       │   ├── page.tsx        # Landing page with Clerk Auth state
│       │   ├── dashboard/      # Protected dashboard route
│       │   ├── sign-in/        # Clerk SignIn route
│       │   └── sign-up/        # Clerk SignUp route
│       ├── middleware.ts       # Clerk route protection proxy
│       └── .env.example
│
├── packages/
│   ├── api-client/             # Reusable client + generated OpenAPI types
│   ├── types/                  # Generic TypeScript types (ApiResponse, AuthUser)
│   ├── validators/             # Generic Zod validation schemas
│   ├── eslint-config/          # Shared ESLint configuration
│   └── tsconfig/               # Shared TypeScript configurations
│
├── tooling/
│   └── scripts/
│       └── generate-api.mjs    # OpenAPI-to-TypeScript client generator
│
├── turbo.json
├── pnpm-workspace.yaml
├── package.json
└── README.md
```

---

## Quickstart

### 1. Prerequisites
- Node.js >= 20
- pnpm >= 10
- Python >= 3.11
- uv >= 0.5

### 2. Install Dependencies

```bash
# Install JavaScript dependencies across the monorepo:
pnpm install

# Sync Python backend virtual environment:
uv sync --project apps/api --extra dev
```

### 3. Run the Applications

#### Run Backend API (FastAPI)
```bash
uv run --project apps/api uvicorn app.main:app --reload --port 8000
```
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)
- **OpenAPI Schema**: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

#### Run Frontend (Next.js)
```bash
pnpm --filter web dev
```
- Available at [http://localhost:3000](http://localhost:3000)
- Sign-In route: [http://localhost:3000/sign-in](http://localhost:3000/sign-in)
- Protected Dashboard: [http://localhost:3000/dashboard](http://localhost:3000/dashboard)

#### Run Both Concurrently via Turbo
```bash
pnpm dev
```

---

## Testing & Quality Assurance

```bash
# Backend pytest suite:
uv run --project apps/api pytest apps/api/tests

# Frontend production build:
pnpm --filter web build

# Shared packages type checking:
pnpm typecheck
```

---

## Regenerating the TypeScript API Client

Whenever the backend OpenAPI schema changes, regenerate the TypeScript types:

```bash
pnpm generate:api
```
This exports `apps/api/openapi.json` and compiles it into `packages/api-client/src/generated/schema.ts`.
