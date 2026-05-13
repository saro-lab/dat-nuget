using System.Text;

namespace Saro.Dat;

public class DatManager
{
    private DatCertificate? _issuer;
    private List<DatCertificate> _certificates = new();
    private readonly ReaderWriterLockSlim _lock = new();

    public string Issue(byte[] plain, byte[] secure)
    {
        _lock.EnterReadLock();
        try
        {
            if (_issuer == null) throw new DatException("Not Found IssuanceKey(SigningKey)");
            return Issue(_issuer, plain, secure);
        }
        finally { _lock.ExitReadLock(); }
    }

    public string Issue(string plain, string secure) =>
        Issue(Encoding.UTF8.GetBytes(plain), Encoding.UTF8.GetBytes(secure));

    public DatPayload Parse(string datStr) => Parse(new Dat(datStr));

    public DatPayload Parse(Dat dat)
    {
        _lock.EnterReadLock();
        try
        {
            var cert = FindUnsafe(dat.Cid);
            return Parse(cert, dat);
        }
        finally { _lock.ExitReadLock(); }
    }

    internal DatCertificate FindUnsafe(long cid) =>
        _certificates.Find(c => c.Cid == cid) ?? throw new DatException($"Not Found CID: {cid:x}");

    public void Imports(string format, bool clear)
    {
        var certs = string.IsNullOrWhiteSpace(format)
            ? new List<DatCertificate>()
            : format.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(DatCertificate.Parse).ToList();
        Imports(certs, clear);
    }

    public void Imports(List<DatCertificate> certs, bool clear)
    {
        if (certs.Count != certs.Select(c => c.Cid).Distinct().Count())
            throw new ArgumentException("Duplicate CID(Certificate ID)");

        _lock.EnterWriteLock();
        try
        {
            List<DatCertificate> list;
            if (clear)
            {
                list = certs.Where(c => !c.Expired).ToList();
            }
            else
            {
                var existing = _certificates.Select(c => (DatCertificate)c.Clone()).ToList();
                foreach (var nc in certs)
                {
                    if (!existing.Any(e => e.Cid == nc.Cid)) existing.Add(nc);
                }
                list = existing.Where(c => !c.Expired).ToList();
            }

            _certificates = list.OrderBy(c => c.IssueEnd).ToList();
            _issuer = _certificates.LastOrDefault(c => c.Issuable);
        }
        finally { _lock.ExitWriteLock(); }
    }

    public static string Issue(DatCertificate certificate, byte[] plain, byte[] secure)
    {
        long expire = Unixtime.Now() + certificate.Ttl;
        string header = $"{expire}.{certificate.Cid:x}.{DatUtils.EncodeBase64Url(plain)}.{DatUtils.EncodeBase64Url(certificate.CryptoKey.Encrypt(secure))}";
        byte[] signature = certificate.SignatureKey.Sign(Encoding.UTF8.GetBytes(header));
        return $"{header}.{DatUtils.EncodeBase64Url(signature)}";
    }

    public static string Issue(DatCertificate certificate, string plain, string secure) =>
        Issue(certificate, Encoding.UTF8.GetBytes(plain), Encoding.UTF8.GetBytes(secure));

    public static DatPayload Parse(DatCertificate certificate, Dat dat)
    {
        if (!certificate.SignatureKey.Verify(dat.Body, dat.SignatureBytes))
            throw new DatException("Invalid Dat Signature");

        return ParseWithoutVerifying(certificate, dat);
    }

    public static DatPayload Parse(DatCertificate certificate, string datStr) => Parse(certificate, new Dat(datStr));

    public static DatPayload ParseWithoutVerifying(DatCertificate certificate, Dat dat) =>
        new DatPayload(dat.PlainBytes, certificate.CryptoKey.Decrypt(dat.SecureBytes));

    public static DatManager NewInstance() => new DatManager();
}
