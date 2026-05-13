using System.Text;

namespace Saro.Dat.Tests;

public class CryptoTest
{
    private void Unit(DatCryptoAlgorithm alg)
    {
        var body = Encoding.UTF8.GetBytes(DatUtils.GenerateRandomBase62(100));
        var cryptoKey = IDatCryptoKey.Generate(alg);
        var cryptoKeyFail = IDatCryptoKey.Generate(alg);
        var cryptoKeyBytes = cryptoKey.ToBytes();
        var cryptoKeyFrom = IDatCryptoKey.FromBytes(alg, cryptoKeyBytes);

        var encrypted = cryptoKeyFrom.Encrypt(body);

        Assert.That(cryptoKey.Decrypt(encrypted), Is.EqualTo(body));
        Assert.That(cryptoKeyFrom.Decrypt(encrypted), Is.EqualTo(body));
        Assert.That(() => cryptoKeyFail.Decrypt(encrypted), Throws.Exception);
    }

    [Test]
    public void Test()
    {
        foreach (DatCryptoAlgorithm algorithm in Enum.GetValues<DatCryptoAlgorithm>())
        {
            TestContext.Progress.WriteLine($"crypto test - {algorithm}");
            for (int i = 0; i < 20; i++)
            {
                Unit(algorithm);
            }
        }
    }
}
