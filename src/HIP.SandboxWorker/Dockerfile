# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
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
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "HIP.SandboxWorker.dll"]
