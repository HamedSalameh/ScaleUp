using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Shared.Contracts
{
    public interface IModuleInstaller
    {
        void Install(IServiceCollection services, IConfiguration configuration);
    }
}
