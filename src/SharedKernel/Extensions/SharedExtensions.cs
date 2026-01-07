using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shared.Contracts;
using System.Reflection;

namespace SharedKernel.Extensions
{
    public static class SharedExtensions
    {
        public static IServiceCollection InstallModulesFromAssemblies(
            this IServiceCollection services,
            IConfiguration configuration,
            params Assembly[] assemblies)
        {
            var installers = assemblies
                .SelectMany(a => a.DefinedTypes)
                .Where(t => typeof(IModuleInstaller).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
                .Select(Activator.CreateInstance)
                .Cast<IModuleInstaller>()
                .ToList();

            foreach (var installer in installers)
                installer.Install(services, configuration);

            return services;
        }
    }
}
