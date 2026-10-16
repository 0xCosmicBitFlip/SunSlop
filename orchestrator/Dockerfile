# docker build -f orchestrator/Dockerfile -t gs-orchestrator:local .
# Proxy pods compile gs-relay on start from the source copied here. The image
# carries the compiler, not a prebuilt relay binary. GS_ROLE=orchestrator
# skips that compile.
FROM fedora:44
RUN dnf -y install python3 python3-cryptography rust cargo gcc && dnf clean all
COPY orchestrator/orchestrator.py /usr/local/bin/orchestrator.py
COPY orchestrator/moonlight_proxy.py /usr/local/bin/moonlight_proxy.py
COPY orchestrator/gs /usr/local/bin/gs
COPY orchestrator/gs-relay /usr/local/src/gs-relay
COPY orchestrator/relay-build.sh /usr/local/bin/relay-build.sh
COPY orchestrator/entrypoint.sh /usr/local/bin/gs-entrypoint
RUN chmod 0755 /usr/local/bin/relay-build.sh /usr/local/bin/gs-entrypoint \
    && rm -rf /usr/local/src/gs-relay/target
USER root
ENTRYPOINT ["/usr/local/bin/gs-entrypoint"]
