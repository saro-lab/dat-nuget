using System.Security.Cryptography;

namespace Saro.Dat;

public class DatCryptoAesGcmNonce : IDatCrypto
{
    private readonly DatCryptoAlgorithm _algorithm;
    private readonly byte[] _key;
    private const int NonceLen = 12;
    private const int TagLen = 16;

    private DatCryptoAesGcmNonce(DatCryptoAlgorithm algorithm, byte[] key)
    {
        _algorithm = algorithm;
        _key = key;
    }

    public static IDatCrypto FromBytes(DatCryptoAlgorithm alg, byte[] bytes)
    {
        if (bytes.Length != GetKeySize(alg))
        {
            throw new DatException($"Invalid {alg} Key Size: {bytes.Length}");
        }
        return new DatCryptoAesGcmNonce(alg, bytes);
    }

    public static IDatCrypto Generate(DatCryptoAlgorithm alg)
    {
        byte[] key = new byte[GetKeySize(alg)];
        RandomNumberGenerator.Fill(key);
        return new DatCryptoAesGcmNonce(alg, key);
    }

    private static int GetKeySize(DatCryptoAlgorithm alg) => alg switch
    {
        DatCryptoAlgorithm.IvAes128Gcm => 16,
        DatCryptoAlgorithm.IvAes256Gcm => 32,
        _ => throw new ArgumentException($"Unsupported crypto algorithm: {alg}")
    };

    public byte[] Encrypt(byte[] bytes)
    {
        byte[] nonce = new byte[NonceLen];
        RandomNumberGenerator.Fill(nonce);
        byte[] tag = new byte[TagLen];
        byte[] ciphertext = new byte[bytes.Length];

        using var aes = new AesGcm(_key, TagLen);
        aes.Encrypt(nonce, bytes, ciphertext, tag);

        byte[] result = new byte[NonceLen + ciphertext.Length + TagLen];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceLen);
        Buffer.BlockCopy(ciphertext, 0, result, NonceLen, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceLen + ciphertext.Length, TagLen);
        return result;
    }

    public byte[] Decrypt(byte[] bytes)
    {
        if (bytes.Length < NonceLen + TagLen) throw new DatException("Invalid Encrypted Data");

        byte[] nonce = bytes[..NonceLen];
        byte[] ciphertext = bytes[NonceLen..^TagLen];
        byte[] tag = bytes[^TagLen..];
        byte[] plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(_key, TagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    public DatCryptoAlgorithm Algorithm() => _algorithm;
    public byte[] ToBytes() => (byte[])_key.Clone();
    public object Clone() => new DatCryptoAesGcmNonce(_algorithm, (byte[])_key.Clone());
    IDatCrypto IDatCrypto.Clone() => (IDatCrypto)Clone();
}
