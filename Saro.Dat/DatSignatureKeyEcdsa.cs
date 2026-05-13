using System.Security.Cryptography;

namespace Saro.Dat;

public class DatSignatureKeyEcdsa : IDatSignatureKey
    {
        private readonly DatSignatureAlgorithm _algorithm;
        private readonly ECDsa _ecdsa;
        private readonly bool _hasPrivate;

        private DatSignatureKeyEcdsa(DatSignatureAlgorithm alg, ECDsa ecdsa, bool hasPrivate)
        {
            _algorithm = alg;
            _ecdsa = ecdsa;
            _hasPrivate = hasPrivate;
        }

        public static IDatSignatureKey Generate(DatSignatureAlgorithm alg)
        {
            var curve = GetCurve(alg);
            return new DatSignatureKeyEcdsa(alg, ECDsa.Create(curve), true);
        }

        public static IDatSignatureKey FromBytes(DatSignatureAlgorithm alg, byte[]? priv, byte[] pub)
        {
            var ecdsa = ECDsa.Create();
            var hasPrivate = false;

            ECParameters parameters = new ECParameters { Curve = GetCurve(alg) };

            if (priv != null && priv.Length > 0)
            {
                parameters.D = priv;
                ecdsa.ImportParameters(parameters);
                hasPrivate = true;
            }

            if (pub.Length > 0)
            {
                // 공용키 복원 (Uncompressed 포맷 04 + X + Y 처리)
                int keySize = GetKeySize(alg);
                parameters.Q = new ECPoint
                {
                    X = pub[1..(1 + keySize)],
                    Y = pub[(1 + keySize)..]
                };
                ecdsa.ImportParameters(parameters);
            }
            else if (!hasPrivate)
            {
                throw new DatException("Invalid Signature Key");
            }

            return new DatSignatureKeyEcdsa(alg, ecdsa, hasPrivate);
        }

        public byte[] Sign(byte[] body) => _hasPrivate ? _ecdsa.SignData(body, GetHashName(_algorithm), DSASignatureFormat.IeeeP1363FixedFieldConcatenation) : throw new Exception("No private key");

        public bool Verify(byte[] body, byte[] signature) => _ecdsa.VerifyData(body, signature, GetHashName(_algorithm), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public byte[]? GetSigningKeyBytes() => _hasPrivate ? _ecdsa.ExportParameters(true).D : null;

        public byte[] GetVerifyingKeyBytes()
        {
            var params0 = _ecdsa.ExportParameters(false);
            byte[] res = new byte[1 + params0.Q.X!.Length + params0.Q.Y!.Length];
            res[0] = 0x04;
            Buffer.BlockCopy(params0.Q.X, 0, res, 1, params0.Q.X.Length);
            Buffer.BlockCopy(params0.Q.Y, 0, res, 1 + params0.Q.X.Length, params0.Q.Y.Length);
            return res;
        }

        private static ECCurve GetCurve(DatSignatureAlgorithm alg) => alg switch
        {
            DatSignatureAlgorithm.P256 => ECCurve.NamedCurves.nistP256,
            DatSignatureAlgorithm.P384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521
        };

        private static HashAlgorithmName GetHashName(DatSignatureAlgorithm alg) => alg switch
        {
            DatSignatureAlgorithm.P256 => HashAlgorithmName.SHA256,
            DatSignatureAlgorithm.P384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512
        };

        private static int GetKeySize(DatSignatureAlgorithm alg) => alg switch { DatSignatureAlgorithm.P256 => 32, DatSignatureAlgorithm.P384 => 48, _ => 66 };

        public DatSignatureAlgorithm Algorithm() => _algorithm;
        public bool HasSigningKey() => _hasPrivate;
        public object Clone() => FromBytes(_algorithm, GetSigningKeyBytes(), GetVerifyingKeyBytes());
    }

