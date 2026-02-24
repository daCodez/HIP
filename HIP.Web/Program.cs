using HIP.ServiceDefaults;
using HIP.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddRazorComponents();

builder.Services.AddHttpClient("hip-api", client =>
{
    client.BaseAddress = new Uri("https+http://hip-api");
});

var app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>();
app.MapDefaultEndpoints();

app.Run();
