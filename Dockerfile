FROM node:24-alpine AS deps
WORKDIR /app
ENV HUSKY=0
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
# Skip lifecycle scripts (husky prepare) in the image build.
RUN pnpm install --frozen-lockfile --ignore-scripts

FROM node:24-alpine AS build
WORKDIR /app
ENV HUSKY=0
RUN corepack enable
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./package.json
COPY tsconfig.json ./
COPY src ./src
# prune removes husky; --ignore-scripts prevents prepare from failing.
RUN pnpm run build && pnpm prune --prod --ignore-scripts

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
EXPOSE 8000
USER node
CMD ["node", "dist/index.js"]
