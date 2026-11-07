# NOTE: the recommended way to run the backend is directly on the host with systemd
# (see deploy/neora-backend.service and the root README.md). The backend starts sibling
# Docker containers, so it needs the Docker CLI and daemon access, and it mounts its own
# files into those containers by host path. This image copies the full backend source,
# but it does not include the Docker CLI; extend it yourself if you want to run the
# backend itself in a container, and never expose the Docker socket to untrusted code.
FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY *.mjs ./
COPY security ./security
COPY fetcher ./fetcher
COPY probe ./probe
COPY sandbox ./sandbox
USER node
CMD ["node","server.mjs"]
