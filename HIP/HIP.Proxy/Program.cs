using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseForwardedHeaders();
app.MapGet("/", () => Results.Redirect("/admin", permanent: false));
app.MapGet("/aspire", () => Results.Redirect("https://srv1377835-1.tailb59890.ts.net:8446/", permanent: false));
app.MapGet("/aspire/{**catchall}", () => Results.Redirect("https://srv1377835-1.tailb59890.ts.net:8446/", permanent: false));
app.MapReverseProxy();

app.Run();
