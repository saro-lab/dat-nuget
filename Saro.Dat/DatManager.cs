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
            if (_issuer != null) return Issue(_issuer, plain, secure);
        }
        finally { _lock.ExitReadLock(); }
        throw new DatException("Not Found IssuanceKey(SigningKey)");
    }

    public string Issue(string plain, string secure) =>
        Issue(Encoding.UTF8.GetBytes(plain), Encoding.UTF8.GetBytes(secure));

    public Payload Parse(Dat dat)
    {
        _lock.EnterReadLock();
        try
        {
            return Parse(FindUnsafe(dat.Cid), dat);
        }
        finally { _lock.ExitReadLock(); }
    }

    public Payload Parse(string datStr) => Parse(new Dat(datStr));

    public Payload ParseWithoutVerifying(Dat dat)
    {
        _lock.EnterReadLock();
        try
        {
            return ParseWithoutVerifying(FindUnsafe(dat.Cid), dat);
        }
        finally { _lock.ExitReadLock(); }
    }

    public Payload ParseWithoutVerifying(string datStr) => ParseWithoutVerifying(new Dat(datStr));

    internal DatCertificate FindUnsafe(long cid) =>
        _certificates.Find(c => c.Cid == cid) ?? throw new DatException($"Not Found CID(Certificate ID): {cid:x}");

    public List<long> ExportsIds()
    {
        _lock.EnterReadLock();
        try { return _certificates.Select(c => c.Cid).ToList(); }
        finally { _lock.ExitReadLock(); }
    }

    public List<DatCertificate> ExportsCertificates()
    {
        _lock.EnterReadLock();
        try { return _certificates.Select(c => (DatCertificate)c.Clone()).ToList(); }
        finally { _lock.ExitReadLock(); }
    }

    public string Exports(bool verifyOnly)
    {
        _lock.EnterReadLock();
        try { return string.Join("\n", _certificates.Select(c => c.Exports(verifyOnly))); }
        finally { _lock.ExitReadLock(); }
    }

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
                    if (!existing.Contains(nc)) existing.Add(nc);
                }
                list = existing.Where(c => !c.Expired).ToList();
            }

            _certificates = list.OrderBy(c => c.IssueEnd).ToList();
            _issuer = _certificates.LastOrDefault(c => c.Issuable)?.Clone() as DatCertificate;
        }
        finally { _lock.ExitWriteLock(); }
    }

    public static string Issue(DatCertificate certificate, byte[] plain, byte[] secure)
    {
        using var ms = new MemoryStream();

        // expire
        long expire = Unixtime.Now() + certificate.Ttl;
        ms.Write(Encoding.UTF8.GetBytes(expire.ToString()));
        ms.WriteByte((byte)'.');

        // cid
        ms.Write(Encoding.UTF8.GetBytes(certificate.Cid.ToString("x")));
        ms.WriteByte((byte)'.');

        // plain
        ms.Write(Encoding.UTF8.GetBytes(DatUtils.EncodeBase64Url(plain)));
        ms.WriteByte((byte)'.');

        // secure
        ms.Write(Encoding.UTF8.GetBytes(DatUtils.EncodeBase64Url(certificate.Crypto.Encrypt(secure))));

        byte[] header = ms.ToArray();
        byte[] signature = certificate.Signature.Sign(header);

        return $"{Encoding.UTF8.GetString(header)}.{DatUtils.EncodeBase64Url(signature)}";
    }

    public static string Issue(DatCertificate certificate, string plain, string secure) =>
        Issue(certificate, Encoding.UTF8.GetBytes(plain), Encoding.UTF8.GetBytes(secure));

    public static Payload Parse(DatCertificate certificate, Dat dat)
    {
        if (!certificate.Signature.Verify(dat.Body, dat.SignatureBytes))
            throw new DatException("Invalid Dat Signature");

        return ParseWithoutVerifying(certificate, dat);
    }

    public static Payload Parse(DatCertificate certificate, string datStr) => Parse(certificate, new Dat(datStr));

    public static Payload ParseWithoutVerifying(DatCertificate certificate, Dat dat) =>
        new Payload(dat.PlainBytes, certificate.Crypto.Decrypt(dat.SecureBytes));

    public static Payload ParseWithoutVerifying(DatCertificate certificate, string datStr) =>
        ParseWithoutVerifying(certificate, new Dat(datStr));

    public static DatManager NewInstance() => new DatManager();

    internal static DatManager NewInstance(List<DatCertificate> certificates)
    {
        var manager = NewInstance();
        manager.Imports(certificates, true);
        return manager;
    }
}
