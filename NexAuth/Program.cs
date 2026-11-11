namespace NexAuth
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter in a TOTP Secret: ");
            var secret = Console.ReadLine();

            Console.WriteLine("OTP Code: " + OTPGenerator.GenerateFromSecret(secret));
        }
    }
}