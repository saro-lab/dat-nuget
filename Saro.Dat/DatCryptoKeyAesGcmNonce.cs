using System.Security.Cryptography;

namespace Saro.Dat;

public class DatCryptoKeyAesGcmNonce : IDatCryptoKey
{
    private readonly DatCryptoAlgorithm _algorithm;
    private readonly byte[] _key;
    private const int NonceLen = 12;
    private const int TagLen = 16;

    private DatCryptoKeyAesGcmNonce(DatCryptoAlgorithm algorithm, byte[] key)
    {
        _algorithm = algorithm;
        _key = key;
    }

    public static IDatCryptoKey FromBytes(DatCryptoAlgorithm alg, byte[] bytes) => new DatCryptoKeyAesGcmNonce(alg, bytes);

    public static IDatCryptoKey Generate(DatCryptoAlgorithm alg)
    {
        int size = alg == DatCryptoAlgorithm.AES128GCMN ? 16 : 32;
        byte[] key = new byte[size];
        RandomNumberGenerator.Fill(key);
        return new DatCryptoKeyAesGcmNonce(alg, key);
    }

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
    public object Clone() => new DatCryptoKeyAesGcmNonce(_algorithm, (byte[])_key.Clone());
}
