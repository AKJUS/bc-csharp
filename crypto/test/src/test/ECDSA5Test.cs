using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
    public class ECDsa5Test
    {
//		private static readonly byte[] k1 = Hex.Decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
//		private static readonly byte[] k2 = Hex.Decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");
//
//		private SecureRandom Random = FixedSecureRandom.From(k1, k2);

        [Test]
        public void DecodeTest()
        {
            ECCurve curve = new FpCurve(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

            ECPoint p = curve.DecodePoint(Hex.Decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"));

            BigInteger x = p.AffineXCoord.ToBigInteger();

            if (!x.Equals(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)))
            {
                Assert.Fail("x uncompressed incorrectly");
            }

            BigInteger y = p.AffineYCoord.ToBigInteger();
            if (!y.Equals(new BigInteger("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)))
            {
                Assert.Fail("y uncompressed incorrectly");
            }
        }

        /**
        * X9.62 - 1998,<br/>
        * J.3.2, Page 155, ECDSA over the field Fp<br/>
        * an example with 239 bit prime
        */
        [Test]
        public void TestECDsa239BitPrime()
        {
            BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
            BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

            byte[] kData = new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655").ToByteArrayUnsigned();

            SecureRandom k = FixedSecureRandom.From(kData);

//			EllipticCurve curve = new EllipticCurve(
//				new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
//				new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
//				new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
            ECCurve curve = new FpCurve(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

            ECDomainParameters spec = new ECDomainParameters(
                curve,
//				ECPointUtil.DecodePoint(curve, Hex.Decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                curve.DecodePoint(Hex.Decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                BigInteger.One); //1); // h

            ECPrivateKeyParameters sKey = new ECPrivateKeyParameters(
                "ECDSA",
                new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
                spec);

            ECPublicKeyParameters vKey = new ECPublicKeyParameters(
                "ECDSA",
//				ECPointUtil.DecodePoint(curve, Hex.Decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
                curve.DecodePoint(Hex.Decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
                spec);

            ISigner sgr = SignerUtilities.GetSigner("ECDSA");
//			KeyFactory f = KeyFactory.getInstance("ECDSA");
//			AsymmetricKeyParameter sKey = f.generatePrivate(priKey);
//			AsymmetricKeyParameter vKey = f.generatePublic(pubKey);

            sgr.Init(true, new ParametersWithRandom(sKey, k));

            byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

            sgr.BlockUpdate(message, 0, message.Length);

            byte[] sigBytes = sgr.GenerateSignature();

            sgr.Init(false, vKey);

            sgr.BlockUpdate(message, 0, message.Length);

            if (!sgr.VerifySignature(sigBytes))
            {
                Assert.Fail("239 Bit EC verification failed");
            }

            BigInteger[] sig = DerDecode(sigBytes);

            if (!r.Equals(sig[0]))
            {
                Assert.Fail("r component wrong." + SimpleTest.NewLine
                    + " expecting: " + r + SimpleTest.NewLine
                    + " got      : " + sig[0]);
            }

            if (!s.Equals(sig[1]))
            {
                Assert.Fail("s component wrong." + SimpleTest.NewLine
                    + " expecting: " + s + SimpleTest.NewLine
                    + " got      : " + sig[1]);
            }
        }

        /**
        * X9.62 - 1998,<br/>
        * J.2.1, Page 100, ECDSA over the field F2m<br/>
        * an example with 191 bit binary field
        */
        [Test]
        public void TestECDsa239BitBinary()
        {
            BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
            BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");
        
            byte[] kData = new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363").ToByteArrayUnsigned();

            SecureRandom k = FixedSecureRandom.From(kData);

//			EllipticCurve curve = new EllipticCurve(
//				new ECFieldF2m(239, // m
//							new int[] { 36 }), // k
//				new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
//				new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
            ECCurve curve = new F2mCurve(
                239, // m
                36, // k
                new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
                new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b

            ECDomainParameters parameters = new ECDomainParameters(
                curve,
//				ECPointUtil.DecodePoint(curve, Hex.Decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
                curve.DecodePoint(Hex.Decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
                new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
                BigInteger.Four); //4); // h

            ECPrivateKeyParameters sKey = new ECPrivateKeyParameters(
                "ECDSA",
                new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
                parameters);

            ECPublicKeyParameters vKey = new ECPublicKeyParameters(
                "ECDSA",
//				ECPointUtil.DecodePoint(curve, Hex.Decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
                curve.DecodePoint(Hex.Decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
                parameters);

            ISigner sgr = SignerUtilities.GetSigner("ECDSA");
//			KeyFactory f = KeyFactory.getInstance("ECDSA");
//			AsymmetricKeyParameter sKey = f.generatePrivate(priKeySpec);
//			AsymmetricKeyParameter vKey = f.generatePublic(pubKeySpec);
            byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

            sgr.Init(true, new ParametersWithRandom(sKey, k));

            sgr.BlockUpdate(message, 0, message.Length);

            byte[] sigBytes = sgr.GenerateSignature();

            sgr.Init(false, vKey);

            sgr.BlockUpdate(message, 0, message.Length);

            if (!sgr.VerifySignature(sigBytes))
            {
                Assert.Fail("239 Bit EC verification failed");
            }

            BigInteger[] sig = DerDecode(sigBytes);

            if (!r.Equals(sig[0]))
            {
                Assert.Fail("r component wrong." + SimpleTest.NewLine
                    + " expecting: " + r + SimpleTest.NewLine
                    + " got      : " + sig[0]);
            }

            if (!s.Equals(sig[1]))
            {
                Assert.Fail("s component wrong." + SimpleTest.NewLine
                    + " expecting: " + s + SimpleTest.NewLine
                    + " got      : " + sig[1]);
            }
        }

        // test BSI algorithm support.
        [Test]
        public void TestBSI()
        {
            var random = new SecureRandom();

            var kpg = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            kpg.Init(new ECKeyGenerationParameters(TeleTrusTObjectIdentifiers.BrainpoolP512R1, random));

            var kp = kpg.GenerateKeyPair();

            byte[] data = Encoding.UTF8.GetBytes("Hello World!!!");
            string[] cvcAlgs = { "SHA1WITHCVC-ECDSA", "SHA224WITHCVC-ECDSA", "SHA256WITHCVC-ECDSA",
                "SHA384WITHCVC-ECDSA", "SHA512WITHCVC-ECDSA" };
            DerObjectIdentifier[] cvcOids = { EacObjectIdentifiers.id_TA_ECDSA_SHA_1,
                EacObjectIdentifiers.id_TA_ECDSA_SHA_224, EacObjectIdentifiers.id_TA_ECDSA_SHA_256,
                EacObjectIdentifiers.id_TA_ECDSA_SHA_384, EacObjectIdentifiers.id_TA_ECDSA_SHA_512 };

            ImplTestBsiAlgorithms(kp, data, cvcAlgs, cvcOids);

            string[] plainAlgs = { "SHA1WITHPLAIN-ECDSA", "SHA224WITHPLAIN-ECDSA", "SHA256WITHPLAIN-ECDSA",
                "SHA384WITHPLAIN-ECDSA", "SHA512WITHPLAIN-ECDSA", "RIPEMD160WITHPLAIN-ECDSA", "SHA3-224WITHPLAIN-ECDSA",
                "SHA3-256WITHPLAIN-ECDSA", "SHA3-384WITHPLAIN-ECDSA", "SHA3-512WITHPLAIN-ECDSA" };
            DerObjectIdentifier[] plainOids = { BsiObjectIdentifiers.ecdsa_plain_SHA1,
                BsiObjectIdentifiers.ecdsa_plain_SHA224, BsiObjectIdentifiers.ecdsa_plain_SHA256,
                BsiObjectIdentifiers.ecdsa_plain_SHA384, BsiObjectIdentifiers.ecdsa_plain_SHA512,
                BsiObjectIdentifiers.ecdsa_plain_RIPEMD160, BsiObjectIdentifiers.ecdsa_plain_SHA3_224,
                BsiObjectIdentifiers.ecdsa_plain_SHA3_256, BsiObjectIdentifiers.ecdsa_plain_SHA3_384,
                BsiObjectIdentifiers.ecdsa_plain_SHA3_512 };

            ImplTestBsiAlgorithms(kp, data, plainAlgs, plainOids);

            //kpg = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            var kgp = new ECKeyGenerationParameters(SecObjectIdentifiers.SecP521r1, random);
            kpg.Init(kgp);

            kp = kpg.GenerateKeyPair();

            ImplTestBsiSigSize(kp, kgp.DomainParameters.N, "SHA224WITHPLAIN-ECDSA");
        }

        [Test]
        public void TestGeneration()
        {
            //
            // ECDSA generation test
            //
            byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
            ISigner s = SignerUtilities.GetSigner("ECDSA");
            IAsymmetricCipherKeyPairGenerator g = GeneratorUtilities.GetKeyPairGenerator("ECDSA");

//			EllipticCurve curve = new EllipticCurve(
//				new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
//				new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
//				new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
            ECCurve curve = new FpCurve(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

            ECDomainParameters ecSpec = new ECDomainParameters(
                curve,
//				ECPointUtil.DecodePoint(curve,
                curve.DecodePoint(
                    Hex.Decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                BigInteger.One); //1); // h

            g.Init(new ECKeyGenerationParameters(ecSpec, new SecureRandom()));

            AsymmetricCipherKeyPair p = g.GenerateKeyPair();

            AsymmetricKeyParameter sKey = p.Private;
            AsymmetricKeyParameter vKey = p.Public;

            s.Init(true, sKey);

            s.BlockUpdate(data, 0, data.Length);

            byte[] sigBytes = s.GenerateSignature();

            s = SignerUtilities.GetSigner("ECDSA");

            s.Init(false, vKey);

            s.BlockUpdate(data, 0, data.Length);

            if (!s.VerifySignature(sigBytes))
            {
                Assert.Fail("ECDSA verification failed");
            }
        }

        private static BigInteger[] DerDecode(byte[] encoding)
        {
            Asn1Sequence s = Asn1Sequence.GetInstance(encoding);

            return new BigInteger[]
            {
                ((DerInteger)s[0]).Value,
                ((DerInteger)s[1]).Value
            };
        }

        private static void ImplTestBsiAlgorithms(AsymmetricCipherKeyPair kp, byte[] data, string[] algs,
            DerObjectIdentifier[] oids)
        {
            for (int i = 0; i != algs.Length; i++)
            {
                var sig1 = SignerUtilities.GetSigner(algs[i]);
                var sig2 = SignerUtilities.GetSigner(oids[i]);

                sig1.Init(forSigning: true, kp.Private);
                sig1.BlockUpdate(data, 0, data.Length);

                byte[] sig = sig1.GenerateSignature();

                sig2.Init(forSigning: false, kp.Public);
                sig2.BlockUpdate(data, 0, data.Length);

                Assert.True(sig2.VerifySignature(sig), "BSI CVC signature failed: " + algs[i]);
            }
        }

        private static void ImplTestBsiSigSize(AsymmetricCipherKeyPair kp, BigInteger order, string alg)
        {
            for (int i = 0; i != 20; i++)
            {
                var sig1 = SignerUtilities.GetSigner(alg);
                var sig2 = SignerUtilities.GetSigner(alg);

                sig1.Init(forSigning: true, kp.Private);
                sig1.Update((byte)i);

                byte[] sig = sig1.GenerateSignature();

                Assert.AreEqual(2 * ((order.BitLength + 7) / 8), sig.Length);
                sig2.Init(forSigning: false, kp.Public);
                sig2.Update((byte)i);

                Assert.True(sig2.VerifySignature(sig), "BSI CVC signature failed: " + alg);
            }
        }
    }
}
