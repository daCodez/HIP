FROM quay.io/keycloak/keycloak:26.7.0@sha256:0f198be292568439d700cdbfb893e69a6009bb43a94a06a945b1d3d506c76b13 AS builder

ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.7.0@sha256:0f198be292568439d700cdbfb893e69a6009bb43a94a06a945b1d3d506c76b13

ARG HIP_RELEASE_REVISION=unknown
ARG HIP_RELEASE_VERSION=0.0.0-unset
LABEL org.opencontainers.image.source="https://github.com/daCodez/HIP" \
      org.opencontainers.image.revision="$HIP_RELEASE_REVISION" \
      org.opencontainers.image.version="$HIP_RELEASE_VERSION"

COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY --chmod=0755 deploy/keycloak/configure-federated-providers.sh /opt/keycloak/bin/hip-configure-federated-providers.sh
COPY --chown=keycloak:keycloak deploy/keycloak/themes/ /opt/keycloak/themes/
COPY --chown=keycloak:keycloak src/HIP.Web/wwwroot/hip-logo.svg /opt/keycloak/themes/hip/login/resources/img/hip-logo.svg

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
