# Dedicated offline detonation image. Runtime packages are used only inside a one-shot,
# network-disabled container with dropped capabilities and a read-only sample mount.
FROM node:22-alpine
RUN apk add --no-cache python3 bash ruby php83 perl lua5.4 \
 && ln -sf /usr/bin/php83 /usr/local/bin/php \
 && ln -sf /usr/bin/lua5.4 /usr/local/bin/lua
