using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Nsri;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Security
{
    public static class ParameterUtilities
    {
        private static readonly IDictionary<string, string> Algorithms =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly IDictionary<string, int> BasicIVSizes =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        static ParameterUtilities()
        {
            AddAlgorithm("AES",
                "AESWRAP");
            AddAlgorithm("AES128",
                SecurityUtilities.WrongAes128,
                NistObjectIdentifiers.IdAes128Cbc,
                NistObjectIdentifiers.IdAes128Ccm,
                NistObjectIdentifiers.IdAes128Cfb,
                NistObjectIdentifiers.IdAes128Ecb,
                NistObjectIdentifiers.IdAes128Gcm,
                NistObjectIdentifiers.IdAes128Ofb,
                NistObjectIdentifiers.IdAes128Wrap,
                NistObjectIdentifiers.IdAes128WrapPad);
            AddAlgorithm("AES192",
                SecurityUtilities.WrongAes192,
                NistObjectIdentifiers.IdAes192Cbc,
                NistObjectIdentifiers.IdAes192Ccm,
                NistObjectIdentifiers.IdAes192Cfb,
                NistObjectIdentifiers.IdAes192Ecb,
                NistObjectIdentifiers.IdAes192Gcm,
                NistObjectIdentifiers.IdAes192Ofb,
                NistObjectIdentifiers.IdAes192Wrap,
                NistObjectIdentifiers.IdAes192WrapPad);
            AddAlgorithm("AES256",
                SecurityUtilities.WrongAes256,
                NistObjectIdentifiers.IdAes256Cbc,
                NistObjectIdentifiers.IdAes256Ccm,
                NistObjectIdentifiers.IdAes256Cfb,
                NistObjectIdentifiers.IdAes256Ecb,
                NistObjectIdentifiers.IdAes256Gcm,
                NistObjectIdentifiers.IdAes256Ofb,
                NistObjectIdentifiers.IdAes256Wrap,
                NistObjectIdentifiers.IdAes256WrapPad);
            AddAlgorithm("ARIA");
            AddAlgorithm("ARIA128",
                NsriObjectIdentifiers.id_aria128_cbc,
                NsriObjectIdentifiers.id_aria128_ccm,
                NsriObjectIdentifiers.id_aria128_cfb,
                NsriObjectIdentifiers.id_aria128_ctr,
                NsriObjectIdentifiers.id_aria128_ecb,
                NsriObjectIdentifiers.id_aria128_gcm,
                NsriObjectIdentifiers.id_aria128_kw,
                NsriObjectIdentifiers.id_aria128_kwp,
                NsriObjectIdentifiers.id_aria128_ocb2,
                NsriObjectIdentifiers.id_aria128_ofb);
            AddAlgorithm("ARIA192",
                NsriObjectIdentifiers.id_aria192_cbc,
                NsriObjectIdentifiers.id_aria192_ccm,
                NsriObjectIdentifiers.id_aria192_cfb,
                NsriObjectIdentifiers.id_aria192_ctr,
                NsriObjectIdentifiers.id_aria192_ecb,
                NsriObjectIdentifiers.id_aria192_gcm,
                NsriObjectIdentifiers.id_aria192_kw,
                NsriObjectIdentifiers.id_aria192_kwp,
                NsriObjectIdentifiers.id_aria192_ocb2,
                NsriObjectIdentifiers.id_aria192_ofb);
            AddAlgorithm("ARIA256",
                NsriObjectIdentifiers.id_aria256_cbc,
                NsriObjectIdentifiers.id_aria256_ccm,
                NsriObjectIdentifiers.id_aria256_cfb,
                NsriObjectIdentifiers.id_aria256_ctr,
                NsriObjectIdentifiers.id_aria256_ecb,
                NsriObjectIdentifiers.id_aria256_gcm,
                NsriObjectIdentifiers.id_aria256_kw,
                NsriObjectIdentifiers.id_aria256_kwp,
                NsriObjectIdentifiers.id_aria256_ocb2,
                NsriObjectIdentifiers.id_aria256_ofb);
            AddAlgorithm("BLOWFISH",
                /*
                 * TODO[api] Incorrect version of cryptlib_algorithm_blowfish_CBC
                 * Remove at major version update and delete bad test data "pbes2.bf-cbc.key"
                 */
                "1.3.6.1.4.1.3029.1.2",
                MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC);
            AddAlgorithm("CAMELLIA",
                "CAMELLIAWRAP");
            AddAlgorithm("CAMELLIA128",
                NttObjectIdentifiers.IdCamellia128Cbc,
                NttObjectIdentifiers.IdCamellia128Wrap);
            AddAlgorithm("CAMELLIA192",
                NttObjectIdentifiers.IdCamellia192Cbc,
                NttObjectIdentifiers.IdCamellia192Wrap);
            AddAlgorithm("CAMELLIA256",
                NttObjectIdentifiers.IdCamellia256Cbc,
                NttObjectIdentifiers.IdCamellia256Wrap);
            AddAlgorithm("CAST5",
                MiscObjectIdentifiers.cast5CBC);
            AddAlgorithm("CAST6");
            AddAlgorithm("CHACHA");
            AddAlgorithm("CHACHA7539",
                "CHACHA20",
                "CHACHA20-POLY1305",
                PkcsObjectIdentifiers.IdAlgAeadChaCha20Poly1305);
            AddAlgorithm("DES",
                OiwObjectIdentifiers.DesCbc,
                OiwObjectIdentifiers.DesCfb,
                OiwObjectIdentifiers.DesEcb,
                OiwObjectIdentifiers.DesOfb);
            AddAlgorithm("DESEDE",
                "DESEDEWRAP",
                "TDEA",
                OiwObjectIdentifiers.DesEde,
                PkcsObjectIdentifiers.IdAlgCms3DesWrap);
            AddAlgorithm("DESEDE3",
                PkcsObjectIdentifiers.DesEde3Cbc);
            AddAlgorithm("GOST28147",
                "GOST",
                "GOST-28147",
                CryptoProObjectIdentifiers.GostR28147Gcfb);
            AddAlgorithm("HC128");
            AddAlgorithm("HC256");
            AddAlgorithm("IDEA",
                MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC);
            AddAlgorithm("NOEKEON");
            AddAlgorithm("RC2",
                PkcsObjectIdentifiers.RC2Cbc,
                PkcsObjectIdentifiers.IdAlgCmsRC2Wrap);
            AddAlgorithm("RC4",
                "ARC4",
                PkcsObjectIdentifiers.rc4);
            AddAlgorithm("RC5",
                "RC5-32");
            AddAlgorithm("RC5-64");
            AddAlgorithm("RC6");
            AddAlgorithm("RIJNDAEL");
            AddAlgorithm("SALSA20");
            AddAlgorithm("SEED",
                KisaObjectIdentifiers.IdNpkiAppCmsSeedWrap,
                KisaObjectIdentifiers.IdSeedCbc);
            AddAlgorithm("SERPENT");
            AddAlgorithm("SKIPJACK");
            AddAlgorithm("SM4");
            AddAlgorithm("TEA");
            AddAlgorithm("THREEFISH-256");
            AddAlgorithm("THREEFISH-512");
            AddAlgorithm("THREEFISH-1024");
            AddAlgorithm("TNEPRES");
            AddAlgorithm("TWOFISH");
            AddAlgorithm("VMPC");
            AddAlgorithm("VMPC-KSA3");
            AddAlgorithm("XTEA");

            AddBasicIVSizeEntries(8, "BLOWFISH", "CHACHA", "DES", "DESEDE", "DESEDE3", "SALSA20");
            AddBasicIVSizeEntries(12, "CHACHA7539");
            AddBasicIVSizeEntries(16, "AES", "AES128", "AES192", "AES256", "ARIA", "ARIA128", "ARIA192", "ARIA256",
                "CAMELLIA", "CAMELLIA128", "CAMELLIA192", "CAMELLIA256", "NOEKEON", "SEED", "SM4");

            // TODO These algorithms support an IV
            // but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
            // "RIJNDAEL", "SKIPJACK", "TWOFISH"
        }

        private static void AddAlgorithm(string canonicalName, params object[] aliases)
        {
            Algorithms[canonicalName] = canonicalName;

            foreach (object alias in aliases)
            {
                Algorithms[alias.ToString()] = canonicalName;
            }
        }

        private static void AddBasicIVSizeEntries(int size, params string[] algorithms)
        {
            foreach (string algorithm in algorithms)
            {
                BasicIVSizes.Add(algorithm, size);
            }
        }

        public static string GetCanonicalAlgorithmName(string algorithm)
        {
            return CollectionUtilities.GetValueOrNull(Algorithms, algorithm);
        }

        public static KeyParameter CreateKeyParameter(DerObjectIdentifier algOid, byte[] keyBytes)
        {
            return CreateKeyParameter(algOid.Id, keyBytes, 0, keyBytes.Length);
        }

        public static KeyParameter CreateKeyParameter(string algorithm, byte[] keyBytes)
        {
            return CreateKeyParameter(algorithm, keyBytes, 0, keyBytes.Length);
        }

        public static KeyParameter CreateKeyParameter(
            DerObjectIdentifier algOid,
            byte[]				keyBytes,
            int					offset,
            int					length)
        {
            return CreateKeyParameter(algOid.Id, keyBytes, offset, length);
        }

        public static KeyParameter CreateKeyParameter(
            string	algorithm,
            byte[]	keyBytes,
            int		offset,
            int		length)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string canonical = GetCanonicalAlgorithmName(algorithm);

            if (canonical == null)
                throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");

            if (canonical == "DES")
                return new DesParameters(keyBytes, offset, length);

            if (canonical == "DESEDE" || canonical =="DESEDE3")
                return new DesEdeParameters(keyBytes, offset, length);

            if (canonical == "RC2")
                return new RC2Parameters(keyBytes, offset, length);

            return new KeyParameter(keyBytes, offset, length);
        }

        public static ICipherParameters GetCipherParameters(
            DerObjectIdentifier	algOid,
            ICipherParameters	key,
            Asn1Object			asn1Params)
        {
            return GetCipherParameters(algOid.Id, key, asn1Params);
        }

        public static ICipherParameters GetCipherParameters(
            string				algorithm,
            ICipherParameters	key,
            Asn1Object			asn1Params)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            if (NistObjectIdentifiers.IdAes128Gcm.Id.Equals(algorithm) ||
                NistObjectIdentifiers.IdAes192Gcm.Id.Equals(algorithm) ||
                NistObjectIdentifiers.IdAes256Gcm.Id.Equals(algorithm))
            {
                if (!(key is KeyParameter keyParameter))
                    throw new ArgumentException("key data must be accessible for GCM operation");

                var gcmParameters = GcmParameters.GetInstance(asn1Params);

                return new AeadParameters(keyParameter, gcmParameters.IcvLen * 8, gcmParameters.GetNonce());
            }

            if (NistObjectIdentifiers.IdAes128Ccm.Id.Equals(algorithm) ||
                NistObjectIdentifiers.IdAes192Ccm.Id.Equals(algorithm) ||
                NistObjectIdentifiers.IdAes256Ccm.Id.Equals(algorithm))
            {
                if (!(key is KeyParameter keyParameter))
                    throw new ArgumentException("key data must be accessible for CCM operation");

                var ccmParameters = CcmParameters.GetInstance(asn1Params);

                return new AeadParameters(keyParameter, ccmParameters.IcvLen * 8, ccmParameters.GetNonce());
            }

            string canonical = GetCanonicalAlgorithmName(algorithm);

            if (canonical == null)
                throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");

            Asn1OctetString iv = null;

            try
            {
                // TODO These algorithms support an IV
                // but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
                // "RIJNDAEL", "SKIPJACK", "TWOFISH"

                int basicIVKeySize = FindBasicIVSize(canonical);
                if (basicIVKeySize != -1
                    || canonical == "RIJNDAEL" || canonical == "SKIPJACK" || canonical == "TWOFISH")
                {
                    iv = Asn1OctetString.GetInstance(asn1Params);
                }
                else if (canonical == "CAST5")
                {
                    iv = Cast5CbcParameters.GetInstance(asn1Params).IV;
                }
                else if (canonical == "IDEA")
                {
                    iv = IdeaCbcPar.GetInstance(asn1Params).IV;
                }
                else if (canonical == "RC2")
                {
                    iv = RC2CbcParameter.GetInstance(asn1Params).IV;
                }
            }
            catch (Exception e)
            {
                throw new ArgumentException("Could not process ASN.1 parameters", e);
            }

            if (iv != null)
            {
                return new ParametersWithIV(key, iv.GetOctets());
            }

            throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");
        }

        public static Asn1Encodable GenerateParameters(
            DerObjectIdentifier algID,
            SecureRandom		random)
        {
            return GenerateParameters(algID.Id, random);
        }

        public static Asn1Encodable GenerateParameters(
            string			algorithm,
            SecureRandom	random)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            string canonical = GetCanonicalAlgorithmName(algorithm);

            if (canonical == null)
                throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");

            // TODO These algorithms support an IV
            // but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
            // "RIJNDAEL", "SKIPJACK", "TWOFISH"

            int basicIVKeySize = FindBasicIVSize(canonical);
            if (basicIVKeySize != -1)
                return CreateIVOctetString(random, basicIVKeySize);

            if (canonical == "CAST5")
                return new Cast5CbcParameters(CreateIV(random, 8), 128);

            if (canonical == "IDEA")
                return new IdeaCbcPar(CreateIV(random, 8));

            if (canonical == "RC2")
                return new RC2CbcParameter(CreateIV(random, 8));

            throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");
        }

        public static ICipherParameters GetContext(ICipherParameters cipherParameters, int minLen, int maxLen,
            out byte[] context)
        {
            if (cipherParameters is ParametersWithContext withContext)
            {
                int len = withContext.ContextLength;
                if (len < minLen || len > maxLen)
                {
                    var message = $"Context length must be in range [{minLen}, {maxLen}]";
                    throw new ArgumentOutOfRangeException(nameof(cipherParameters), len, message);
                }

                context = withContext.GetContext();
                return withContext.Parameters;
            }

            context = null;
            return cipherParameters;
        }

        public static ICipherParameters GetRandom(ICipherParameters cipherParameters, out SecureRandom random)
        {
            if (cipherParameters is ParametersWithRandom withRandom)
            {
                random = withRandom.Random;
                return withRandom.Parameters;
            }

            random = null;
            return cipherParameters;
        }

        public static ICipherParameters IgnoreRandom(ICipherParameters cipherParameters)
        {
            if (cipherParameters is ParametersWithRandom withRandom)
                return withRandom.Parameters;

            return cipherParameters;
        }

        public static ICipherParameters WithContext(ICipherParameters cp, byte[] context)
        {
            if (context != null)
            {
                cp = new ParametersWithContext(cp, context);
            }
            return cp;
        }

        public static ICipherParameters WithRandom(ICipherParameters cp, SecureRandom random)
        {
            if (random != null)
            {
                cp = new ParametersWithRandom(cp, random);
            }
            return cp;
        }

        private static Asn1OctetString CreateIVOctetString(SecureRandom random, int ivLength)
        {
            return new DerOctetString(CreateIV(random, ivLength));
        }

        private static byte[] CreateIV(SecureRandom random, int ivLength)
        {
            return SecureRandom.GetNextBytes(random, ivLength);
        }

        private static int FindBasicIVSize(string canonicalName)
        {
            return BasicIVSizes.TryGetValue(canonicalName, out int keySize) ? keySize : -1;
        }
    }
}
