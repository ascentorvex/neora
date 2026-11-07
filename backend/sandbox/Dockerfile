# Optional detonation image: lets the inspector RUN .exe/.bat/.vbs (wine), ELF binaries, .sh and .py files
# and trace them with strace. Without this image Neora falls back to node:22-alpine (ELF/.sh only, no tracing).
#   docker build -t neora-detonator:1 backend/sandbox          (several minutes, ~1.5 GB because of wine)
#   docker build --build-arg WITH_WINE=0 -t neora-detonator:1 backend/sandbox   (no Windows support, much smaller)
FROM node:22-bookworm-slim
ARG WITH_WINE=1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends strace python3 ca-certificates \
 && if [ "$WITH_WINE" = "1" ]; then \
      dpkg --add-architecture i386 && apt-get update \
   && apt-get install -y --no-install-recommends wine wine64 wine32:i386 libwine libwine:i386 xvfb xauth \
   && WINEPREFIX=/opt/wineprefix WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=" xvfb-run -a wineboot --init || true; \
      chmod -R a+rX /opt/wineprefix 2>/dev/null || true; \
    fi \
 && rm -rf /var/lib/apt/lists/*
