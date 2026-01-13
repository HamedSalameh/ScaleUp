using System.Reflection;

namespace Auth.Infrastructure
{
    // Renamed to avoid CS0436 conflict with Auth.Domain.AssemblyReference
    public static class InfrastructureAssemblyReference
    {
        // This is here so we can easily get a reference to this assembly
        public static readonly Assembly Assembly = typeof(InfrastructureAssemblyReference).Assembly;
    }
}
