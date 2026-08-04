FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG HIP_RELEASE_REVISION=development
ARG HIP_RELEASE_VERSION=development

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bind9-dnsutils ca-certificates curl pdns-backend-sqlite3 pdns-server sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && usermod --uid 1656 pdns \
    && groupmod --gid 1656 pdns \
    && install -d -o 1656 -g 1656 -m 0700 /var/lib/powerdns \
    && sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql \
    && chown 1656:1656 /var/lib/powerdns/pdns.sqlite3 \
    && chmod 0600 /var/lib/powerdns/pdns.sqlite3

COPY deploy/powerdns/pdns.conf /etc/powerdns/pdns.conf
COPY deploy/powerdns/entrypoint.sh /usr/local/bin/hip-powerdns-entrypoint

RUN sed -i 's/\r$//' /usr/local/bin/hip-powerdns-entrypoint \
    && chmod 0755 /usr/local/bin/hip-powerdns-entrypoint

LABEL org.opencontainers.image.title="HIP authoritative DNS" \
      org.opencontainers.image.revision="${HIP_RELEASE_REVISION}" \
      org.opencontainers.image.version="${HIP_RELEASE_VERSION}"

USER 1656:1656
EXPOSE 5300/tcp 5300/udp 8081/tcp
VOLUME ["/var/lib/powerdns"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=12 \
    CMD ["pdns_control", "rping"]

ENTRYPOINT ["/usr/local/bin/hip-powerdns-entrypoint"]
