namespace Saro.Dat;

public class DatCertificate : ICloneable
{
    public long Cid { get; }
    internal IDatSignatureKey SignatureKey { get; }
    internal IDatCryptoKey CryptoKey { get; }
    public long IssueBegin { get; }
    public long IssueEnd { get; }
    public long Ttl { get; }

    private DatCertificate(long cid, IDatSignatureKey sk, IDatCryptoKey ck, long ib, long ie, long ttl)
    {
        Cid = cid;
        SignatureKey = sk;
        CryptoKey = ck;
        IssueBegin = ib;
        IssueEnd = ie;
        Ttl = ttl;
    }

    public bool Expired => IssueEnd + Ttl < Unixtime.Now();
    public bool Issuable => SignatureKey.HasSigningKey() && Unixtime.Now() >= IssueBegin && Unixtime.Now() <= IssueEnd;

    public string Exports(DatSignatureKeyOutOption option)
    {
        string skBase64 = option switch
        {
            DatSignatureKeyOutOption.FULL => $"{DatUtils.EncodeBase64Url(SignatureKey.GetSigningKeyBytes()!)}~{DatUtils.EncodeBase64Url(SignatureKey.GetVerifyingKeyBytes())}",
            DatSignatureKeyOutOption.SIGNING => DatUtils.EncodeBase64Url(SignatureKey.GetSigningKeyBytes()!),
            DatSignatureKeyOutOption.VERIFYING => $"~{DatUtils.EncodeBase64Url(SignatureKey.GetVerifyingKeyBytes())}",
            _ => throw new ArgumentOutOfRangeException(nameof(option))
        };

        string cryptKeyBase64 = DatUtils.EncodeBase64Url(CryptoKey.ToBytes());
        return $"{Cid:x}.{SignatureKey.Algorithm()}.{skBase64}.{CryptoKey.Algorithm()}.{cryptKeyBase64}.{IssueBegin}.{IssueEnd}.{Ttl}";
    }

    public object Clone() => new DatCertificate(Cid, (IDatSignatureKey)SignatureKey.Clone(), (IDatCryptoKey)CryptoKey.Clone(), IssueBegin, IssueEnd, Ttl);

    public override bool Equals(object? obj)
    {
        if (obj is DatCertificate other) return this.Cid == other.Cid;
        return false;
    }

    public override int GetHashCode() => Cid.GetHashCode();

    public static DatCertificate Generate(long cid, DatSignatureAlgorithm sa, DatCryptoAlgorithm ca, long ib, long ie, long ttl)
    {
        return new DatCertificate(
            cid,
            IDatSignatureKey.Generate(sa),
            IDatCryptoKey.Generate(ca),
            ib,
            ie,
            ttl
        );
    }

    public static DatCertificate New(long cid, IDatSignatureKey sk, IDatCryptoKey ck, long ib, long ie, long ttl)
    {
        return new DatCertificate(cid, sk, ck, ib, ie, ttl);
    }

    public static DatCertificate Parse(string format)
    {
        try
        {
            var p = format.Split('.');
            if (p.Length != 8) throw new DatException("Invalid Dat Certificate Format");

            long cid = Convert.ToInt64(p[0], 16);
            var sigAlg = Enum.Parse<DatSignatureAlgorithm>(p[1]);

            var skParts = p[2].Split('~');
            IDatSignatureKey sigKey;
            if (skParts.Length == 2)
            {
                sigKey = IDatSignatureKey.FromBytes(sigAlg, DatUtils.DecodeBase64Url(skParts[0]), DatUtils.DecodeBase64Url(skParts[1]));
            }
            else if (skParts.Length == 1)
            {
                if (p[2].StartsWith('~'))
                    sigKey = IDatSignatureKey.FromBytes(sigAlg, null, DatUtils.DecodeBase64Url(p[2][1..]));
                else
                    sigKey = IDatSignatureKey.FromBytes(sigAlg, DatUtils.DecodeBase64Url(skParts[0]), Array.Empty<byte>());
            }
            else throw new DatException("Invalid Dat Signature Key Format");

            var cryAlg = Enum.Parse<DatCryptoAlgorithm>(p[3]);
            var cryKey = IDatCryptoKey.FromBytes(cryAlg, DatUtils.DecodeBase64Url(p[4]));

            return new DatCertificate(cid, sigKey, cryKey, long.Parse(p[5]), long.Parse(p[6]), long.Parse(p[7]));
        }
        catch (System.Exception e)
        {
            if (e is DatException) throw;
            throw new DatException("Invalid Dat Signature Format");
        }
    }
}
