# Build stage ---------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files first so restore is cached independently of source edits.
COPY SecureVault.slnx ./
COPY src/SecureVault.Api/SecureVault.Api.csproj src/SecureVault.Api/
COPY tests/SecureVault.Tests/SecureVault.Tests.csproj tests/SecureVault.Tests/
RUN dotnet restore src/SecureVault.Api/SecureVault.Api.csproj

COPY . .
RUN dotnet publish src/SecureVault.Api/SecureVault.Api.csproj \
    -c Release \
    -o /app \
    --no-restore

# Runtime stage -------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# curl is here only so the container can report its own health.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

# Data-protection keys must survive restarts, or every stored TOTP secret
# becomes undecryptable. docker-compose mounts a volume here.
RUN mkdir -p /var/securevault/keys && chown -R app:app /var/securevault

COPY --from=build --chown=app:app /app ./

ENV DataProtection__KeyPath=/var/securevault/keys \
    ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

# The aspnet image ships a non-root "app" user. Running as root would turn a
# remote code execution bug into container root for free.
USER app

HEALTHCHECK --interval=30s --timeout=3s --start-period=25s --retries=3 \
    CMD curl --fail --silent http://localhost:8080/health || exit 1

ENTRYPOINT ["dotnet", "SecureVault.Api.dll"]
