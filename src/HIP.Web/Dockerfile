# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS softhsm-build
ARG OPENSSL_REVISION=8cf17aaeb4599f8af87fefd810b5b5fee90fe69e
ARG SOFTHSM_REVISION=f12916ee8c6eb5c0025786479fcbf6b38480b134
RUN apt-get update \
    && apt-get install -y --no-install-recommends autoconf automake build-essential ca-certificates git libltdl-dev libsqlite3-dev libtool perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/openssl
RUN git init \
    && git remote add origin https://github.com/openssl/openssl.git \
    && git fetch --depth 1 origin "$OPENSSL_REVISION" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$OPENSSL_REVISION"
RUN ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl/ssl shared \
    && make -j2 \
    && make install_sw
RUN test -d /opt/openssl/lib64 \
    && ln -s lib64 /opt/openssl/lib
WORKDIR /build/softhsm
RUN git init \
    && git remote add origin https://github.com/softhsm/SoftHSMv2.git \
    && git fetch --depth 1 origin "$SOFTHSM_REVISION" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$SOFTHSM_REVISION"
RUN sh autogen.sh \
    && ./configure --prefix=/usr/local --enable-mldsa --with-objectstore-backend-db --with-openssl=/opt/openssl \
    && grep -q '^#define WITH_ML_DSA' config.h \
    && make -j2 \
    && make DESTDIR=/opt/softhsm-root install

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:f1126d438ccc359f51cc6d4701a8deae513856cf10f5fe645d29ea6403dcac6b AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libltdl7 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 1654 -g 1654 /var/lib/softhsm/tokens
COPY --from=softhsm-build /opt/softhsm-root/usr/local/ /usr/local/
COPY --from=softhsm-build /opt/openssl/ /opt/openssl/
COPY deploy/softhsm/softhsm2.conf /etc/softhsm2.conf
ENV PATH=/opt/openssl/bin:$PATH \
    LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib \
    SOFTHSM2_CONF=/etc/softhsm2.conf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://localhost:8080/alive || exit 1

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build
WORKDIR /src
COPY HIP.slnx ./
COPY src/HIP.Web/HIP.Web.csproj src/HIP.Web/
COPY src/HIP.Application/HIP.Application.csproj src/HIP.Application/
COPY src/HIP.Domain/HIP.Domain.csproj src/HIP.Domain/
COPY src/HIP.Infrastructure/HIP.Infrastructure.csproj src/HIP.Infrastructure/
COPY src/HIP.ServiceDefaults/HIP.ServiceDefaults.csproj src/HIP.ServiceDefaults/
RUN dotnet restore src/HIP.Web/HIP.Web.csproj
COPY src/ src/
RUN dotnet publish src/HIP.Web/HIP.Web.csproj -c Release -o /app/publish --no-restore

FROM runtime AS final
ARG HIP_RELEASE_REVISION=unknown
ARG HIP_RELEASE_VERSION=0.0.0-unset
LABEL org.opencontainers.image.source="https://github.com/daCodez/HIP" \
      org.opencontainers.image.revision="$HIP_RELEASE_REVISION" \
      org.opencontainers.image.version="$HIP_RELEASE_VERSION"
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "HIP.Web.dll"]
