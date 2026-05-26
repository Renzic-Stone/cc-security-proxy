FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    python3 \
    curl \
    wget \
    openssl \
    coreutils \
    procps \
    strace

RUN adduser -D -s /bin/bash sandbox

RUN mkdir -p /sandbox && chown sandbox:sandbox /sandbox

WORKDIR /sandbox
USER sandbox

ENTRYPOINT ["/bin/bash", "-c"]
