using FastEndpoints;
using FluentValidation;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shared.Contracts;

namespace Auth.Application
{
    public class AuthModuleInstaller : IModuleInstaller
    {
        public void Install(IServiceCollection services, IConfiguration configuration)
        {
            // Load infrastructure dependencies
            //services.AddAuthInfrastructure(configuration);

            // Register application services (handlers, validators, etc.)
            //services.AddScoped<IAuthService, AuthService>();

            services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(AuthModuleInstaller).Assembly));
            services.AddValidatorsFromAssembly(typeof(AuthModuleInstaller).Assembly);
        }
    }
}
