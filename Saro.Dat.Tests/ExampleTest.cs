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
            DatSignatureAlgorithm.P256,
            DatCryptoAlgorithm.AES128GCMN,
            now - 10,
            now + 10,
            1800
        );

        datManager.Imports(new List<DatCertificate> { cert }, false);

        string examplePlain = "plain text = 평문";
        string exampleSecure = "secure = 암호문";

        string dat = datManager.Issue(examplePlain, exampleSecure);

        DatPayload payload = datManager.Parse(dat);

        Assert.That(payload.Plain, Is.EqualTo(examplePlain));
        Assert.That(payload.Secure, Is.EqualTo(exampleSecure));

        TestContext.Progress.WriteLine($"PARSE DAT: {dat}");
        TestContext.Progress.WriteLine($"plain: {payload.Plain}");
        TestContext.Progress.WriteLine($"secure: {payload.Secure}");
    }

    [Test]
    public void TestHard()
    {
        string exampleCerts =
            "0.P256.JH0wsVa7I1P2nyMKNi-REWeIyJ_ja30c8N7JmQpE2Ns.AES128GCMN.29dmalXRXXQT-YNV95HFvg.1.17786821880.1800\n" +
            "1.P256.Gh9fb16c8XYdzKobpUwytD446_cMy3gWyncvViqeIZo.AES128GCMN.zX8sV8zO73-lDSfT-x8I1Q.1.17786821880.1800\n" +
            "2.P256.fsufFa3ByNffCTG0fSQhEZqGF2z8pWxC3aLbZR6F0f8.AES128GCMN.e4h8InqvA5VvE8OtpjxRMQ.1.17786821880.1800\n" +
            "3.P256.koYkmCZYmvLISg4-tPbksoZ71ay8hEVEWB6aBbexliA.AES128GCMN.7nQ7R5yuFQ3S5Vb07Brawg.1.17786821880.1800\n" +
            "4.P256.Cda0iq0axjTeKhpnqfRFapk4innUjwbd2HEXAzYipAM.AES128GCMN.ttE0ydNaePVMVsGhRmyq8Q.1.17786821880.1800\n" +
            "5.P256.Tf4ZFbD9ZmY_9kyQRlSXKpgy18uyMGAImh48_z4e9XE.AES128GCMN.ifsTUtiUzZY6-CUielQWkw.1.17786821880.1800\n" +
            "6.P256.fRz08K1e3mtebqWwHADKl3G4nZR1V2v6knLU6-r7jG4.AES128GCMN.cEPBfYQVKKSd_adfRkrTJQ.1.17786821880.1800\n" +
            "7.P256.HPDwUUi44EWESaenixl1uOkafSc5Yshi9Q5ht5JV-7o.AES128GCMN._WwtaqkFgvqkxv8T5-WHsg.1.17786821880.1800\n" +
            "8.P256.2TSn2rl4Ucc7_tcgLFoba81zMGpdN4zInbgjD_IA0dM.AES128GCMN.zgj82h8PpS0nGxlhJBbUQQ.1.17786821880.1800\n" +
            "9.P256.uKfLtmwS9-4o5_H5fflSoaiCULwHRQXdHan2JSK6-o0.AES128GCMN.w0WXojP3LeCCl68C_KTBMQ.1.1708680188.1800\n";

        string examplePlain = "plain text = 평문";
        string exampleSecure = "secure = 암호문";
        string exampleDat = "19565503600.8.cGxhaW4gdGV4dCA9IO2PieusuA.1YswrtsIMWMz9dJjR2M1sRAZWxzcfTu7CQo-GXaCDMh6nF6g72HQn_F9HnK-kg.kgY9pxi5nITg-8Wk_vRFaUDDldyoSrrOP0-BBxVrwbP0-ZXlpuCmKQ1YiBZd4qv3KrO9vvwZdghpsiYHITbybA";

        var manager = DatManager.NewInstance();

        manager.Imports(exampleCerts, true);

        DatPayload payload = manager.Parse(exampleDat);

        Assert.That(payload.Plain, Is.EqualTo(examplePlain));
        Assert.That(payload.Secure, Is.EqualTo(exampleSecure));

        TestContext.Progress.WriteLine($"PARSE DAT: {exampleDat}");
        TestContext.Progress.WriteLine($"plain: {payload.Plain}");
        TestContext.Progress.WriteLine($"secure: {payload.Secure}");
    }
}
