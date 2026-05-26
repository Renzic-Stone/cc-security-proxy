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
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /sandbox
USER sandbox

ENTRYPOINT ["/entrypoint.sh"]
