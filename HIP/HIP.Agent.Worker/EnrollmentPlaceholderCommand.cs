using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace HIP.Agent.Worker;

public static class EnrollmentPlaceholderCommand
{
    public static bool IsEnrollmentCommand(string[] args)
        => args.Length > 0 && string.Equals(args[0], "enroll", StringComparison.OrdinalIgnoreCase);

    public static async Task<int> RunAsync(string[] args)
    {
        var token = ResolveToken(args);
        if (string.IsNullOrWhiteSpace(token))
        {
            Console.WriteLine("Usage: HIP.Agent.Worker enroll --token <ENROLLMENT_TOKEN>");
            return 1;
        }

        var builder = Host.CreateApplicationBuilder();
        builder.Configuration.SetBasePath(AppContext.BaseDirectory);
        builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
        builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false);

        builder.Services
            .AddOptions<AgentOptions>()
            .Bind(builder.Configuration.GetSection(AgentOptions.SectionName));

        builder.Services.AddHttpClient<EnrollmentClient>();
        builder.Services.AddSingleton<IAgentCredentialStore, FileEncryptedCredentialStore>();

        using var host = builder.Build();

        var client = host.Services.GetRequiredService<EnrollmentClient>();
        var options = host.Services.GetRequiredService<IOptions<AgentOptions>>().Value;
        var store = host.Services.GetRequiredService<IAgentCredentialStore>();

        var response = await client.EnrollAsync(token, CancellationToken.None);
        if (response is null)
        {
            Console.WriteLine("Enrollment failed: API returned non-success status.");
            return 2;
        }

        var credential = new AgentCredential(
            DeviceId: response.DeviceId,
            AssignedIdentity: response.AssignedIdentity,
            BootstrapToken: response.BootstrapToken,
            IssuedAtUtc: response.IssuedAtUtc);

        await store.SaveAsync(credential, CancellationToken.None);

        var path = string.IsNullOrWhiteSpace(options.CredentialStorePath)
            ? Path.Combine(AppContext.BaseDirectory, "agent-credentials.enc")
            : options.CredentialStorePath;

        Console.WriteLine($"Enrollment completed for device '{response.DeviceId}'.");
        Console.WriteLine($"Assigned identity: {response.AssignedIdentity}");
        Console.WriteLine($"Credential material stored at: {path}");
        return 0;
    }

    private static string? ResolveToken(string[] args)
    {
        var tokenIndex = Array.FindIndex(args, a => string.Equals(a, "--token", StringComparison.OrdinalIgnoreCase));
        if (tokenIndex >= 0 && tokenIndex + 1 < args.Length)
        {
            return args[tokenIndex + 1];
        }

        return args.Length >= 2 ? args[1] : null;
    }
}
