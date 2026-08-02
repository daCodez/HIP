# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS softhsm-build
ARG SOFTHSM_REVISION=13e6e86b83748fef74046dbf0c91f664b7acc1c3
RUN apt-get update \
    && apt-get install -y --no-install-recommends autoconf automake build-essential ca-certificates git libltdl-dev libsqlite3-dev libssl-dev libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/softhsm
RUN git init \
    && git remote add origin https://github.com/softhsm/SoftHSMv2.git \
    && git fetch --depth 1 origin "$SOFTHSM_REVISION" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$SOFTHSM_REVISION"
RUN sh autogen.sh \
    && ./configure --prefix=/usr/local --enable-mldsa --with-objectstore-backend-db \
    && make -j2 \
    && make DESTDIR=/opt/softhsm-root install

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:f1126d438ccc359f51cc6d4701a8deae513856cf10f5fe645d29ea6403dcac6b AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libltdl7 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 1654 -g 1654 /var/lib/softhsm/tokens
COPY --from=softhsm-build /opt/softhsm-root/usr/local/ /usr/local/
COPY deploy/softhsm/softhsm2.conf /etc/softhsm2.conf
RUN ldconfig
ENV SOFTHSM2_CONF=/etc/softhsm2.conf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://localhost:8080/alive || exit 1

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build
WORKDIR /src
COPY HIP.slnx ./
COPY src/HIP.ApiService/HIP.ApiService.csproj src/HIP.ApiService/
COPY src/HIP.Application/HIP.Application.csproj src/HIP.Application/
COPY src/HIP.Domain/HIP.Domain.csproj src/HIP.Domain/
COPY src/HIP.Infrastructure/HIP.Infrastructure.csproj src/HIP.Infrastructure/
COPY src/HIP.ServiceDefaults/HIP.ServiceDefaults.csproj src/HIP.ServiceDefaults/
RUN dotnet restore src/HIP.ApiService/HIP.ApiService.csproj
COPY src/ src/
RUN dotnet publish src/HIP.ApiService/HIP.ApiService.csproj -c Release -o /app/publish --no-restore

FROM runtime AS final
ARG HIP_RELEASE_REVISION=unknown
ARG HIP_RELEASE_VERSION=0.0.0-unset
LABEL org.opencontainers.image.source="https://github.com/daCodez/HIP" \
      org.opencontainers.image.revision="$HIP_RELEASE_REVISION" \
      org.opencontainers.image.version="$HIP_RELEASE_VERSION"
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "HIP.ApiService.dll"]
