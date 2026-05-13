namespace Saro.Dat;

public interface IDatCryptoKey : ICloneable
{
    DatCryptoAlgorithm Algorithm();
    byte[] ToBytes();
    byte[] Encrypt(byte[] bytes);
    byte[] Decrypt(byte[] bytes);

    public static IDatCryptoKey FromBytes(DatCryptoAlgorithm algorithm, byte[] bytes)
    {
        return algorithm switch
        {
            DatCryptoAlgorithm.AES128GCMN or DatCryptoAlgorithm.AES256GCMN
                => DatCryptoKeyAesGcmNonce.FromBytes(algorithm, bytes),
            _ => throw new NotSupportedException($"{algorithm} does not support")
        };
    }

    public static IDatCryptoKey Generate(DatCryptoAlgorithm algorithm)
    {
        return algorithm switch
        {
            DatCryptoAlgorithm.AES128GCMN or DatCryptoAlgorithm.AES256GCMN
                => DatCryptoKeyAesGcmNonce.Generate(algorithm),
            _ => throw new NotSupportedException($"{algorithm} does not support")
        };
    }
}
