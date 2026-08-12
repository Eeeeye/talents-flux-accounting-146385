FROM python:3.13-slim-bookworm@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1

RUN groupadd --gid 1000 candidate && \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash candidate

COPY --chown=candidate:candidate task /workspace/flux-accounting
RUN chmod 0755 /workspace/flux-accounting/bin/* \
    /workspace/flux-accounting/scripts/*.py \
    /workspace/flux-accounting/scripts/*.sh && \
    PYTHONPATH=/workspace/flux-accounting/src \
        python3 -B -m compileall -q -f /workspace/flux-accounting/src && \
    find /workspace/flux-accounting -type f -name '*.pyc' -delete && \
    find /workspace/flux-accounting -depth -type d -name '__pycache__' -empty -delete

WORKDIR /workspace/flux-accounting
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/bin/bash"]
