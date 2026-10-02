FROM oven/bun:latest

WORKDIR /app

RUN mkdir -p /data

COPY package.json bun.lock ./

RUN bun install --frozen-lockfile

COPY . .

ARG PUBLIC_BETTER_AUTH_URL
ENV PUBLIC_BETTER_AUTH_URL=${PUBLIC_BETTER_AUTH_URL}
ARG BETTER_AUTH_URL
ENV BETTER_AUTH_URL=${BETTER_AUTH_URL}

RUN bun run build

EXPOSE 3000

ENTRYPOINT ["sh", "docker-entrypoint.sh"]
CMD ["bun", "build/index.js"]
