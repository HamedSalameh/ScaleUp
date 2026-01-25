namespace Auth.Domain
{
    public static class AuthConstants
    {
        public const string BearerTokenType = "Bearer";

        public const int MinEmailLength = 5;
        public const int MaxEmailLength = 50;

        public const int MinFirstNameLength = 2;
        public const int MaxFirstNameLength = 50;

        public const int MinPasswordLength = 8;
        public const int MaxPasswordLength = 100;

    }
}
