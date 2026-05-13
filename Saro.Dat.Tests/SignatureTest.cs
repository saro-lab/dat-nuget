using System.Text;

namespace Saro.Dat.Tests;

public class SignatureTest
{
    private void Unit(DatSignatureAlgorithm alg)
    {
        var body = Encoding.UTF8.GetBytes(DatUtils.GenerateRandomBase62(100));
        var signatureKey = IDatSignatureKey.Generate(alg);
        var signatureKeyFail = IDatSignatureKey.Generate(alg);

        var signingKeyBytes = signatureKey.GetSigningKeyBytes();
        var verifyingKeyBytes = signatureKey.GetVerifyingKeyBytes();

        var signatureKeyFrom = IDatSignatureKey.FromBytes(alg, signingKeyBytes, verifyingKeyBytes);
        var verifyKeyFrom = IDatSignatureKey.FromBytes(alg, null, verifyingKeyBytes);

        var sign = signatureKeyFrom.Sign(body);

        Assert.That(signatureKey.Verify(body, sign), Is.True);
        Assert.That(signatureKeyFrom.Verify(body, sign), Is.True);
        Assert.That(verifyKeyFrom.Verify(body, sign), Is.True);
        Assert.That(signatureKeyFail.Verify(body, sign), Is.False);
    }

    [Test]
    public void Test()
    {
        foreach (DatSignatureAlgorithm algorithm in Enum.GetValues<DatSignatureAlgorithm>())
        {
            TestContext.Progress.WriteLine($"sign test - {algorithm}");
            for (int i = 0; i < 20; i++)
            {
                Unit(algorithm);
            }
        }
    }
}
