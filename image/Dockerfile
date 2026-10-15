# Build from the repo root:
#   docker build -f image/Dockerfile -t gamestream:local .
FROM fedora:44

RUN dnf -y install \
        bash ca-certificates curl jq tar gzip \
        nftables iproute python3 procps-ng \
        shadow-utils passwd util-linux \
        supervisor \
        dbus-daemon dbus-tools \
        labwc foot \
        pipewire pipewire-pulseaudio wireplumber \
        mesa-vulkan-drivers vulkan-loader vulkan-tools \
        mesa-dri-drivers \
        glibc.i686 libstdc++.i686 \
        gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
        gstreamer1-plugins-bad-free \
    && dnf clean all

# RPM Fusion supplies nvh264enc (gstreamer1-plugins-bad-freeworld) and the
# nonfree repo Steam needs later. Sunshine comes from LizardByte's copr.
RUN rel="$(rpm -E %fedora)" \
    && dnf -y install \
        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${rel}.noarch.rpm" \
        "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${rel}.noarch.rpm" \
    && dnf -y install gstreamer1-plugins-bad-freeworld \
    && dnf -y copr enable lizardbyte/stable \
    && dnf -y install Sunshine \
    && dnf clean all

ARG SELKIES_VERSION=
RUN set -eux; \
    if [ -z "$SELKIES_VERSION" ]; then \
      SELKIES_VERSION="$(curl -fsSL https://api.github.com/repos/selkies-project/selkies/releases/latest \
        | jq -r '.tag_name' | sed 's/^v//')"; \
    fi; \
    mkdir -p /opt/selkies; \
    curl -fsSL "https://github.com/selkies-project/selkies/releases/download/v${SELKIES_VERSION}/selkies-gstreamer-portable-v${SELKIES_VERSION}_amd64.tar.gz" \
      | tar -xzf - -C /opt/selkies; \
    launcher="$(find /opt/selkies -type f \( -name 'selkies-gstreamer-run' -o -name 'selkies-gstreamer' \) | head -1)"; \
    test -n "$launcher"; \
    ln -sfn "$launcher" /usr/local/bin/selkies

RUN groupadd -g 1000 gsuser \
    && useradd -u 1000 -g 1000 -m -s /bin/bash gsuser \
    && for g in render video input; do getent group "$g" >/dev/null && usermod -aG "$g" gsuser || true; done

COPY image/ensure-packages.sh /usr/local/bin/ensure-packages.sh
COPY image/entrypoint.sh /usr/local/bin/gamestream-entrypoint
COPY image/seat-boot.py /usr/local/bin/seat-boot.py
COPY image/supervisord.conf /etc/gamestream/supervisord.conf.in
COPY image/labwc-autostart /etc/gamestream/labwc-autostart
COPY image/sunshine.conf /etc/gamestream/sunshine.conf
COPY image/packages.list /etc/gamestream/packages.list

RUN chmod 0755 /usr/local/bin/ensure-packages.sh \
        /usr/local/bin/gamestream-entrypoint \
        /usr/local/bin/seat-boot.py \
    && gst-inspect-1.0 nvh264enc >/dev/null \
    && command -v sunshine \
    && command -v selkies \
    && command -v labwc

# Defaults for a local `docker run`. A seat pod overrides every one of these
# from the gs-config ConfigMap. entrypoint creates the account if it differs.
ENV GS_USER=gsuser \
    GS_UID=1000 \
    GS_GID=1000 \
    GS_HOME=/home/gsuser \
    GS_LAYER=/gs-layer \
    XDG_RUNTIME_DIR=/run/user/1000 \
    WAYLAND_DISPLAY=wayland-0 \
    SELKIES_ENCODER=nvh264enc \
    SELKIES_PORT=8082 \
    SELKIES_ADDR=0.0.0.0 \
    SUNSHINE_BASE_PORT=47989 \
    SUNSHINE_CONFIG_REL=.config/sunshine \
    GS_PROXY_CERT_REQUIRED=0 \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility,graphics,display,video

USER root
ENTRYPOINT ["/usr/local/bin/gamestream-entrypoint"]
