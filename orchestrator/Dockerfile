# docker build -f orchestrator/Dockerfile -t gs-orchestrator:local .
FROM fedora:44
RUN dnf -y install python3 python3-cryptography && dnf clean all
COPY orchestrator/orchestrator.py /usr/local/bin/orchestrator.py
COPY orchestrator/moonlight_proxy.py /usr/local/bin/moonlight_proxy.py
USER root
ENTRYPOINT ["python3", "-u", "/usr/local/bin/orchestrator.py"]
