# BSC Contract Guard — audit endpoint (Node) + bundled bsc-contract-audit skill (python3 rpc.py)
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY vendor ./vendor
COPY samples ./samples
ENV NODE_ENV=production
ENV PORT=7860
# PORT is provided by the host; server.js reads process.env.PORT (default 8791)
CMD ["node", "server.js"]
