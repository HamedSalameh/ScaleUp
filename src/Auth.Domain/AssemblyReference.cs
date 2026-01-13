using System.Reflection;

namespace Auth.Infrastructure
{
    public static class DomainAssemblyReference
    {
        // This is here so we can easily get a reference to this assembly
        public static readonly Assembly Assembly = typeof(DomainAssemblyReference).Assembly;
    }
}
