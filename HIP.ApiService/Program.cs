using HIP.ApiService.Models;
using HIP.Reputation;
using Microsoft.OpenApi;

using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
var redisPassword = builder.Configuration["REDIS_PASSWORD"];
var redisConn = $"localhost:6379,password={redisPassword}";

builder.AddServiceDefaults();
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddOpenApi();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton<IReputationService, ReputationService>();
    builder.Logging.AddDebug();
}
else
{
    builder.Services.AddSingleton<IConnectionMultiplexer>(
        _ => ConnectionMultiplexer.Connect(redisConn));

    builder.Services.AddSingleton<IReputationService, RedisReputationService>();
}


var app = builder.Build();

if (builder.Environment.IsDevelopment())
{

    app.MapOpenApi();
    app.UseSwaggerUI();

}


// Configure the HTTP request pipeline.
app.UseExceptionHandler();

app.MapGet("/", () => "HIP Server running with Aspire!");

app.MapGet("/reputation/{senderId}", async (
    string senderId,
    IReputationService reputationService) =>
{
    var score = await reputationService.GetReputationAsync(senderId);

    return Results.Ok(new
    {
        SenderId = senderId,
        ReputationScore = score
    });
})
.WithOpenApi()
.WithName("GetReputation")
.WithTags("Reputation");

app.MapPost("/hip/message", async (
    HipMessage msg,
    IReputationService reputationService,
    ILogger<Program> logger) =>
{
    bool isSpam = msg.Payload.Contains("spam", StringComparison.OrdinalIgnoreCase);
    await reputationService.UpdateReputationAsync(msg.SenderId, !isSpam);

    double score = await reputationService.GetReputationAsync(msg.SenderId);

    logger.LogInformation("Message from {SenderId} was {Result}. Score: {Score}",
        msg.SenderId,
        isSpam ? "flagged as spam" : "accepted",
        score);

    return Results.Ok(new
    {
        Received = DateTime.UtcNow,
        SenderId = msg.SenderId,
        ReputationScore = score,
        IsSpam = isSpam
    });
});

app.MapDefaultEndpoints();

app.Run();