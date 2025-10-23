using System.Reflection;

namespace Auth.Application
{
    public static class AssemblyReference
    {
        // This is here so we can easily get a reference to this assembly
        public static readonly Assembly Assembly = typeof(AssemblyReference).Assembly;
    }
}
