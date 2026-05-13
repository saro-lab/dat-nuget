namespace Saro.Dat;

public interface IDatSignatureKey : ICloneable
{
    DatSignatureAlgorithm Algorithm();
    bool Verify(byte[] body, byte[] signature);
    byte[] Sign(byte[] body);
    byte[]? GetSigningKeyBytes();
    byte[] GetVerifyingKeyBytes();
    bool HasSigningKey();

    public static IDatSignatureKey FromBytes(DatSignatureAlgorithm algorithm, byte[]? privateKey, byte[] publicKey)
    {
        return algorithm switch
        {
            DatSignatureAlgorithm.P256 or DatSignatureAlgorithm.P384 or DatSignatureAlgorithm.P521
                => DatSignatureKeyEcdsa.FromBytes(algorithm, (privateKey?.Length > 0) ? privateKey : null, publicKey),
            _ => throw new NotSupportedException($"{algorithm} does not support")
        };
    }

    public static IDatSignatureKey Generate(DatSignatureAlgorithm algorithm)
    {
        return algorithm switch
        {
            DatSignatureAlgorithm.P256 or DatSignatureAlgorithm.P384 or DatSignatureAlgorithm.P521
                => DatSignatureKeyEcdsa.Generate(algorithm),
            _ => throw new NotSupportedException($"{algorithm} does not support")
        };
    }
}

