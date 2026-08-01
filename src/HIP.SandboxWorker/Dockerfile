# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:f1126d438ccc359f51cc6d4701a8deae513856cf10f5fe645d29ea6403dcac6b AS runtime
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build
WORKDIR /src
COPY HIP.slnx ./
COPY src/HIP.SandboxWorker/HIP.SandboxWorker.csproj src/HIP.SandboxWorker/
COPY src/HIP.Application/HIP.Application.csproj src/HIP.Application/
COPY src/HIP.Domain/HIP.Domain.csproj src/HIP.Domain/
COPY src/HIP.Infrastructure/HIP.Infrastructure.csproj src/HIP.Infrastructure/
COPY src/HIP.ServiceDefaults/HIP.ServiceDefaults.csproj src/HIP.ServiceDefaults/
RUN dotnet restore src/HIP.SandboxWorker/HIP.SandboxWorker.csproj
COPY src/ src/
RUN dotnet publish src/HIP.SandboxWorker/HIP.SandboxWorker.csproj -c Release -o /app/publish --no-restore

FROM runtime AS final
ARG HIP_RELEASE_REVISION=unknown
ARG HIP_RELEASE_VERSION=0.0.0-unset
LABEL org.opencontainers.image.source="https://github.com/daCodez/HIP" \
      org.opencontainers.image.revision="$HIP_RELEASE_REVISION" \
      org.opencontainers.image.version="$HIP_RELEASE_VERSION"
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "HIP.SandboxWorker.dll"]
