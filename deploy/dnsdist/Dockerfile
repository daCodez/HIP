FROM powerdns/dnsdist-21:2.1.0@sha256:2fc7ef0e0009a419e59082e31e2e42614fd0979c0b1929f72f4755f210c1e521

ARG HIP_RELEASE_REVISION=local
ARG HIP_RELEASE_VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/daCodez/HIP" \
      org.opencontainers.image.revision="${HIP_RELEASE_REVISION}" \
      org.opencontainers.image.version="${HIP_RELEASE_VERSION}" \
      org.opencontainers.image.title="HIP private DNS front door"

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9-dnsutils ca-certificates knot-dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY deploy/dnsdist/dnsdist.conf /etc/dnsdist/dnsdist.conf

USER 953:953
EXPOSE 5353/tcp 5353/udp 853/tcp 853/udp
HEALTHCHECK --interval=30s --timeout=8s --start-period=15s --retries=5 \
    CMD output="$(dig @127.0.0.1 -p 5353 . SOA +dnssec +time=3 +tries=1)" \
        && echo "${output}" | grep -q "status: NOERROR" \
        && echo "${output}" | grep -Eq "flags:.* ad;"
