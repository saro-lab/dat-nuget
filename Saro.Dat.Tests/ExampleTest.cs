namespace Saro.Dat.Tests;

[TestFixture]
public class ExampleTest
{
    [Test]
    public void TestIssueAndParse()
    {
        var datManager = DatManager.NewInstance();

        long now = Unixtime.Now();
        var cert = DatCertificate.Generate(
            0,
            now - 10,
            7200,
            1800,
            DatSignatureAlgorithm.EcdsaP256,
            DatCryptoAlgorithm.IvAes128Gcm
        );

        datManager.Imports(new List<DatCertificate> { cert }, false);

        string examplePlain = "plain text = 평문";
        string exampleSecure = "secure = 암호문";

        string dat = datManager.Issue(examplePlain, exampleSecure);

        Payload payload = datManager.Parse(dat);

        Assert.That(payload.Plain, Is.EqualTo(examplePlain));
        Assert.That(payload.Secure, Is.EqualTo(exampleSecure));

        TestContext.Progress.WriteLine($"PARSE DAT: {dat}");
        TestContext.Progress.WriteLine($"plain: {payload.Plain}");
        TestContext.Progress.WriteLine($"secure: {payload.Secure}");
    }
}
