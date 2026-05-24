namespace Saro.Dat;

public class DatCertificate : ICloneable
{
    public long Cid { get; }
    internal IDatSignature Signature { get; }
    internal IDatCrypto Crypto { get; }
    public long IssueBegin { get; }
    public long IssueEnd { get; }
    public long Ttl { get; }

    private DatCertificate(long cid, IDatSignature sk, IDatCrypto ck, long ib, long ie, long ttl)
    {
        Cid = cid;
        Signature = sk;
        Crypto = ck;
        IssueBegin = ib;
        IssueEnd = ie;
        Ttl = ttl;
    }

    public bool Expired => IssueEnd + Ttl < Unixtime.Now();
    public bool Issuable => Signature.Signable() && Unixtime.Now() >= IssueBegin && Unixtime.Now() <= IssueEnd;

    public string Exports(bool verifyOnly = false)
    {
        return $"{Cid:x}.{IssueBegin}.{IssueEnd - IssueBegin}.{Ttl}.{Signature.Algorithm().ToText()}.{Crypto.Algorithm().ToText()}.{DatUtils.EncodeBase64Url(Signature.ExportKey(verifyOnly))}.{DatUtils.EncodeBase64Url(Crypto.ToBytes())}";
    }

    public override string ToString() => Exports(false);

    public object Clone() => new DatCertificate(Cid, Signature.Clone(), Crypto.Clone(), IssueBegin, IssueEnd, Ttl);

    public override bool Equals(object? obj)
    {
        if (obj is DatCertificate other) return this.Cid == other.Cid;
        return false;
    }

    public override int GetHashCode() => Cid.GetHashCode();

    public static DatCertificate Generate(long cid, long issuedAt, long issuanceDuration, long datTtl, DatSignatureAlgorithm sa, DatCryptoAlgorithm ca)
    {
        return New(
            cid,
            issuedAt,
            issuanceDuration,
            datTtl,
            IDatSignature.Generate(sa),
            IDatCrypto.Generate(ca)
        );
    }

    public static DatCertificate New(long cid, long issuedAt, long issuanceDuration, long datTtl, IDatSignature sk, IDatCrypto ck)
    {
        if (issuedAt < 0) throw new DatException("issuedAt must >= 0");
        if (datTtl < 1) throw new DatException("datTtl must > 0");
        // Kotlin logic: if (issuanceDuration < (datTtl * 2UL) && issuanceDuration < (datTtl + 3600UL))
        if (issuanceDuration < (datTtl * 2) && issuanceDuration < (datTtl + 3600))
        {
            throw new DatException("issuanceDuration must > (datTtl * 2) or (datTtl + 3600)");
        }
        return new DatCertificate(cid, sk, ck, issuedAt, issuedAt + issuanceDuration, datTtl);
    }

    public static DatCertificate Parse(string format)
    {
        try
        {
            var p = format.Split('.');
            if (p.Length == 8)
            {
                long cid = Convert.ToInt64(p[0], 16);
                long issuedAt = long.Parse(p[1]);
                long issuanceDuration = long.Parse(p[2]);
                long datTtl = long.Parse(p[3]);
                var sigAlg = DatSignatureAlgorithmExtensions.FromText(p[4]);
                var cryAlg = DatCryptoAlgorithmExtensions.FromText(p[5]);
                var sigKey = IDatSignature.FromKey(sigAlg, DatUtils.DecodeBase64Url(p[6]));
                var cryKey = IDatCrypto.FromBytes(cryAlg, DatUtils.DecodeBase64Url(p[7]));

                return New(cid, issuedAt, issuanceDuration, datTtl, sigKey, cryKey);
            }
        }
        catch (System.Exception e)
        {
            if (e is DatException) throw;
        }
        throw new DatException("Invalid Dat Certificate Format");
    }
}
