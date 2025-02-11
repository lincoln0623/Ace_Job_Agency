using _233531N_Ace_Job_Agency.Model;
using _233531N_Ace_Job_Agency.Services;
using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages(options =>
{
    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
});
builder.Services.AddDbContext<AppDbContext>();
builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";  // Redirect to the login page
    options.LogoutPath = "/SLogout";  // Redirect after logout
    options.ExpireTimeSpan = TimeSpan.FromSeconds(10);  // Cookie expiration time (30 minutes)
    options.SlidingExpiration = true;  // Extend cookie expiration time on activity
    options.Cookie.HttpOnly = true;  // Prevent client-side access to cookies
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;  // Enforce secure cookies in production (HTTPS)
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache(); //save session in memory
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(10);
});
builder.Services.AddScoped<IUserSessionService, UserSessionService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseSession();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

// Handle 400 Bad Request errors (Anti-Forgery Token Mismatch)
app.UseStatusCodePages(context =>
{
    if (context.HttpContext.Response.StatusCode == 400)
    {
        context.HttpContext.Response.Redirect("/400");
    }
    if (context.HttpContext.Response.StatusCode == 404)
    {
        context.HttpContext.Response.Redirect("/404");
    }
    if (context.HttpContext.Response.StatusCode == 403)
    {
        context.HttpContext.Response.Redirect("/403");
    }
    if (context.HttpContext.Response.StatusCode == 500)
    {
        context.HttpContext.Response.Redirect("/500");
    }

    return Task.CompletedTask;
});

app.MapRazorPages();

app.Run();
