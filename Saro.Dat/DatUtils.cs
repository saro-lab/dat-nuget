using System.Security.Cryptography;

namespace Saro.Dat;

public static class DatUtils
{
    private static readonly char[] MoldBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray();

    public static string EncodeBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');

    public static byte[] DecodeBase64Url(string str)
    {
        if (string.IsNullOrEmpty(str)) return Array.Empty<byte>();
        string base64 = str.Replace("-", "+").Replace("_", "/");
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }

    public static string GenerateRandomBase62(int size)
    {
        var rv = new char[size];
        for (int i = 0; i < size; i++)
        {
            rv[i] = MoldBase62[RandomNumberGenerator.GetInt32(MoldBase62.Length)];
        }
        return new string(rv);
    }
}
