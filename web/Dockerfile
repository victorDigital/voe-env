FROM oven/bun:latest

WORKDIR /app

RUN mkdir -p /data

COPY package.json bun.lock ./

RUN bun install

COPY . .

RUN bun run build

EXPOSE 3000

CMD ["sh", "-c", "if [ ! -f /data/local.db ]; then cp /app/local.db /data/local.db; fi && bun build/index.js"]
