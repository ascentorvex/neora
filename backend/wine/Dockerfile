# neora-wine:1  -  one-shot Windows runtime (Wine) for the Neora sandbox.
# Built ONCE on the host (deploy/build-wine.sh). The backend never builds or pulls it.
FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      wine wine64 libwine fonts-wine wine32:i386 libwine:i386 \
      xvfb strace bash coreutils procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/wine /tmp/home && chown 65534:65534 /opt/wine /tmp/home

# Build the pristine prefix as the SAME uid the sandbox uses at run time (65534), with the SAME HOME,
# so Wine's profile symlinks and ownership checks line up. mono/gecko/menubuilder are disabled.
USER 65534:65534
ENV HOME=/tmp/home WINEPREFIX=/opt/wine WINEARCH=win64 WINEDEBUG=fixme-all DISPLAY=:99 \
    WINEDLLOVERRIDES="mscoree,mshtml,winemenubuilder.exe=d"
RUN mkdir -p /tmp/home \
 && (Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 &) \
 && sleep 2 \
 && wineboot --init \
 && wineserver -w \
 && rm -f /opt/wine/dosdevices/z: \
 && rm -rf /tmp/home /tmp/.X11-unix /tmp/.X99-lock /tmp/.wine-*

# 32-bit self-check: a win64 prefix only runs 32-bit .exe files if SysWOW64 was populated by wineboot.
# If this fails, wine32:i386 is missing or broken. Fail the BUILD instead of failing every 32-bit run later.
RUN test -d /opt/wine/drive_c/windows/syswow64 \
 && test "$(ls /opt/wine/drive_c/windows/syswow64 | wc -l)" -gt 100 \
 && ls /usr/lib/wine/ | head -20

# Runner is copied LAST: editing it later only rebuilds this tiny layer, not the Wine prefix.
COPY --chmod=0755 neora-wine-run /usr/local/bin/neora-wine-run
CMD ["neora-wine-run"]
