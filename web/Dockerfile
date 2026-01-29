FROM oven/bun:latest

WORKDIR /app

RUN mkdir -p /data

COPY package.json bun.lock ./

RUN bun install

COPY . .

# Accept build arguments for public env variables
ARG PUBLIC_BETTER_AUTH_URL
ENV PUBLIC_BETTER_AUTH_URL=${PUBLIC_BETTER_AUTH_URL}

RUN bun run build

EXPOSE 3000

CMD ["bun", "build/index.js"]
