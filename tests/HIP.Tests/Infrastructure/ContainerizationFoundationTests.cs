namespace HIP.Tests.Infrastructure;

/// <summary>
/// Verifies the local container foundation keeps HIP runnable without committing secrets or private data.
/// </summary>
public sealed class ContainerizationFoundationTests
{
    /// <summary>
    /// Confirms Dockerfiles exist for the two runnable HIP services in the current solution.
    /// </summary>
    [Test]
    public void Api_and_web_dockerfiles_exist()
    {
        var root = FindRepositoryRoot();

        Assert.That(File.Exists(Path.Combine(root, "src", "HIP.ApiService", "Dockerfile")), Is.EqualTo(true));
        Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "Dockerfile")), Is.EqualTo(true));
    }

    /// <summary>
    /// Confirms Docker Compose includes production-like dependency containers without requiring a worker service yet.
    /// </summary>
    [Test]
    public void Compose_defines_postgres_redis_queue_api_and_web_services()
    {
        var compose = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "docker-compose.yml"));

        Assert.That(compose, Does.Contain("hip-postgres:"));
        Assert.That(compose, Does.Contain("hip-redis:"));
        Assert.That(compose, Does.Contain("hip-queue:"));
        Assert.That(compose, Does.Contain("hip-api:"));
        Assert.That(compose, Does.Contain("hip-web:"));
    }

    /// <summary>
    /// Confirms container startup relies on environment variables instead of committed secrets.
    /// </summary>
    [Test]
    public void Compose_requires_secret_environment_variables()
    {
        var compose = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "docker-compose.yml"));

        Assert.That(compose, Does.Contain("${HIP_POSTGRES_PASSWORD:?Set HIP_POSTGRES_PASSWORD in .env}"));
        Assert.That(compose, Does.Contain("${HIP_RABBITMQ_PASSWORD:?Set HIP_RABBITMQ_PASSWORD in .env}"));
        Assert.That(compose, Does.Contain("${HIP_RECORD_ENCRYPTION_KEY:?Set HIP_RECORD_ENCRYPTION_KEY in .env}"));
        Assert.That(compose, Does.Contain("${HIP_PRIVACY_HASHING_KEY:?Set HIP_PRIVACY_HASHING_KEY in .env}"));
    }

    /// <summary>
    /// Confirms HIP service images probe the privacy-safe liveness endpoint rather than an authenticated route.
    /// </summary>
    [Test]
    public void Service_dockerfiles_use_alive_health_checks()
    {
        var root = FindRepositoryRoot();
        var apiDockerfile = File.ReadAllText(Path.Combine(root, "src", "HIP.ApiService", "Dockerfile"));
        var webDockerfile = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Dockerfile"));

        Assert.That(apiDockerfile, Does.Contain("http://localhost:8080/alive"));
        Assert.That(webDockerfile, Does.Contain("http://localhost:8080/alive"));
    }

    /// <summary>
    /// Confirms local secret files are ignored so developers do not accidentally commit `.env` values.
    /// </summary>
    [Test]
    public void Gitignore_excludes_local_env_file()
    {
        var gitignore = File.ReadAllText(Path.Combine(FindRepositoryRoot(), ".gitignore"));

        Assert.That(gitignore, Does.Contain(".env"));
        Assert.That(gitignore, Does.Contain("appsettings.Local.json"));
    }

    /// <summary>
    /// Confirms the documentation explains the current Postgres limitation instead of pretending it is active.
    /// </summary>
    [Test]
    public void Container_docs_document_postgres_mvp_limit()
    {
        var docs = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "docs", "containerization.md"));

        Assert.That(docs, Does.Contain("PostgreSQL is staged as a local dependency"));
        Assert.That(docs, Does.Contain("not yet the active EF Core provider"));
    }

    /// <summary>
    /// Finds the repository root from any test output folder.
    /// </summary>
    /// <returns>The absolute repository root.</returns>
    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate HIP.slnx from the test output directory.");
    }
}
