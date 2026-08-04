FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build

ARG UNBOUND_REVISION=c33ad1b1a21e48bfe4f140e90252a9be1b0c5745

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates git libevent-dev libexpat1-dev libssl-dev libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/NLnetLabs/unbound.git /src/unbound \
    && cd /src/unbound \
    && git checkout --detach "${UNBOUND_REVISION}" \
    && test "$(git rev-parse HEAD)" = "${UNBOUND_REVISION}" \
    && autoreconf -fi \
    && ./configure --prefix=/opt/unbound --with-libevent --with-libexpat --with-ssl \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

ARG HIP_RELEASE_REVISION=local
ARG HIP_RELEASE_VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/daCodez/HIP" \
      org.opencontainers.image.revision="${HIP_RELEASE_REVISION}" \
      org.opencontainers.image.version="${HIP_RELEASE_VERSION}" \
      org.opencontainers.image.title="HIP validating DNS resolver"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libevent-2.1-7 libexpat1 libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1655 unbound \
    && useradd --uid 1655 --gid 1655 --home-dir /var/lib/unbound --no-create-home --shell /usr/sbin/nologin unbound \
    && install -d -o 1655 -g 1655 -m 0700 /var/lib/unbound

COPY --from=build /opt/unbound /opt/unbound
COPY deploy/unbound/unbound.conf /etc/unbound/unbound.conf
COPY deploy/unbound/entrypoint.sh /usr/local/bin/hip-unbound-entrypoint

RUN chmod 0755 /usr/local/bin/hip-unbound-entrypoint

ENV PATH="/opt/unbound/sbin:/opt/unbound/bin:${PATH}"
USER 1655:1655
EXPOSE 5353/tcp 5353/udp
VOLUME ["/var/lib/unbound"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=8 \
    CMD ["unbound-control", "-c", "/etc/unbound/unbound.conf", "status"]
ENTRYPOINT ["/usr/local/bin/hip-unbound-entrypoint"]
