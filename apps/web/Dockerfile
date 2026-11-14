# Multi-stage production Dockerfile for Next.js in a pnpm monorepo
FROM node:22-alpine AS base

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Stage 1: Install dependencies
FROM base AS deps
WORKDIR /app

# Copy monorepo package manifests
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json ./
COPY apps/web/package.json ./apps/web/
COPY packages/api-client/package.json ./packages/api-client/
COPY packages/types/package.json ./packages/types/
COPY packages/validators/package.json ./packages/validators/
COPY packages/eslint-config/package.json ./packages/eslint-config/
COPY packages/tsconfig/package.json ./packages/tsconfig/

RUN pnpm install --frozen-lockfile

# Stage 2: Build Next.js application
FROM base AS builder
WORKDIR /app

COPY --from=deps /app ./
COPY apps/web ./apps/web
COPY packages ./packages

# Pass public build-time environment variables
ARG NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=$NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_TELEMETRY_DISABLED=1

RUN pnpm --filter web build

# Stage 3: Minimal production runner
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy standalone build output
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/public ./apps/web/public
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/static ./apps/web/.next/static

USER nextjs

EXPOSE 3000

CMD ["node", "apps/web/server.js"]
