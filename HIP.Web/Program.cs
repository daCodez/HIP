using HIP.ServiceDefaults;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddHttpClient("hip-api", client =>
{
    client.BaseAddress = new Uri("http://hip-api"); // security awareness: internal service DNS
});

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new { Name = "HIP Web", UtcTimestamp = DateTimeOffset.UtcNow }));
app.MapDefaultEndpoints();

app.Run();
