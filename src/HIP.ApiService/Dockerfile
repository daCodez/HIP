# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://localhost:8080/alive || exit 1

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
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
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "HIP.ApiService.dll"]
