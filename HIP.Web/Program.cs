using HIP.ServiceDefaults;
using HIP.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddRazorComponents();

builder.Services.AddHttpClient("hip-api", client =>
{
    client.BaseAddress = new Uri("http://100.67.76.107:5101");
});

var app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>();
app.MapDefaultEndpoints();

app.Run();
