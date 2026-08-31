using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    [TestFixture]
    public class LmsTests
    {
        [Test]
        public void TestCoefFunc()
        {
            byte[] S = Hex.Decode("1234");
            Assert.AreEqual(0, LMOts.Coef(S, 7, 1));
            Assert.AreEqual(1, LMOts.Coef(S, 0, 4));
        }

        [Test]
        public void TestPrivateKeyRound()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, ctx.GetQ(), ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));

            // Recreate signature
            {
                byte[] recreatedSignature = sig.GetEncoded();
                Assert.True(LMOts.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(recreatedSignature), ms, false));
            }

            // Recreate public key.
            {
                byte[] recreatedPubKey = Arrays.Clone(publicKey.GetEncoded());
                Assert.True(LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(recreatedPubKey), sig, ms, false));
            }

            // Vandalise signature
            {

                byte[] vandalisedSignature = sig.GetEncoded();
                vandalisedSignature[256] ^= 1; // Single bit error
                Assert.False(LMOts.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(vandalisedSignature), ms, false));
            }

            // Vandalise public key.
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[50] ^= 1;
                Assert.False(LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false));
            }

            //
            // check incorrect alg type is detected.
            //
            try
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[3] += 1;
                LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false);
                Assert.True(false, "Must fail as public key type not match signature type.");
            }
            catch (LmsException ex)
            {
                Assert.True(ex.Message.Contains("public key and signature ots types do not match"));
            }
        }

        [Test]
        public void TestLMS()
        {
            byte[] msg = Hex.Decode("54686520656e756d65726174696f6e20\n" +
                                    "696e2074686520436f6e737469747574\n" +
                                    "696f6e2c206f66206365727461696e20\n" +
                                    "7269676874732c207368616c6c206e6f\n" +
                                    "7420626520636f6e7374727565642074\n" +
                                    "6f2064656e79206f7220646973706172\n" +
                                    "616765206f7468657273207265746169\n" +
                                    "6e6564206279207468652070656f706c\n" +
                                    "652e0a");

            byte[] seed = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            int level = 1;
            LmsPrivateKeyParameters lmsPrivateKey = Lms.GenerateKeys(
                LMSigParameters.GetParametersByID(5),
                LMOtsParameters.GetParametersByID(4),
                level, Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);

            LmsPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();

            lmsPrivateKey.ExtractKeyShard(3);

            LmsSignature signature = Lms.GenerateSign(lmsPrivateKey, msg);
            Assert.True(Lms.VerifySignature(publicKey, signature, msg));

            // Serialize / Deserialize
            Assert.True(Lms.VerifySignature(
                LmsPublicKeyParameters.GetInstance(publicKey.GetEncoded()),
                LmsSignature.GetInstance(signature.GetEncoded()), msg));

            //
            // Vandalise signature.
            //
            {
                byte[] bustedSig = Arrays.Clone(signature.GetEncoded());
                bustedSig[100] ^= 1;
                Assert.False(Lms.VerifySignature(publicKey, LmsSignature.GetInstance(bustedSig), msg));
            }

            //
            // Vandalise message
            //
            {
                byte[] msg2 = Arrays.Clone(msg);
                msg2[10] ^= 1;
                Assert.False(Lms.VerifySignature(publicKey, signature, msg2));
            }
        }

        [Test]
        public void TestContextSingleUse()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, ctx.GetQ(), ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));

            try
            {
                ctx.Update(1);
                Assert.Fail("Digest reuse after signature taken.");
            }
            catch (NullReferenceException)
            {
                // Expected
            }
        }

        /**
         * Regression test for https://github.com/bcgit/bc-java/issues/2365 - GetEncoded() must carry the top of
         * the Merkle tree so that the first signature made after a key is decoded does not have to rebuild the
         * whole tree (which costs about as much as key generation). Also checks that the legacy encoding, which
         * carries no cache, is still accepted.
         */
        [Test]
        public void TestTreeCachePersistence()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] msg = Hex.Decode("54686520656e756d65726174696f6e20696e2074686520436f6e737469747574");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;

            LmsPrivateKeyParameters privateKey = Lms.GenerateKeys(sigParams, otsParams, 0, I, seed);
            LmsPublicKeyParameters publicKey = privateKey.GetPublicKey();

            int h = sigParams.H;
            int m = sigParams.M;
            int cacheTop = System.Math.Min(64, 1 << (h + 1));

            byte[] enc = privateKey.GetEncoded();

            // 72 byte body + u32 node count + (cacheTop - 1) nodes of m bytes each. The version stays 0 and the
            // cache is appended as trailing data, matching the bc-java interchange format.
            Assert.AreEqual(0, ReadU32(enc, 0));
            Assert.AreEqual(cacheTop - 1, ReadU32(enc, 72));
            Assert.AreEqual(72 + 4 + (cacheTop - 1) * m, enc.Length);

            // The first cached node is the root of the Merkle tree - it must match the public key's T[1].
            byte[] t1 = publicKey.GetT1();
            Assert.True(Arrays.AreEqual(t1, 0, t1.Length, enc, 76, 76 + m));

            // The decoded key signs correctly and byte-identically to a fresh key at the same index.
            LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(enc);
            LmsSignature sigFromDecoded = Lms.GenerateSign(decoded, msg);
            Assert.True(Lms.VerifySignature(publicKey, sigFromDecoded, msg));

            LmsPrivateKeyParameters fresh = Lms.GenerateKeys(sigParams, otsParams, 0, I, seed);
            Assert.True(Arrays.AreEqual(sigFromDecoded.GetEncoded(), Lms.GenerateSign(fresh, msg).GetEncoded()));

            // A corrupted cache node is caught at decode: each cached interior node is recomputed from its
            // cached children and compared before the cache is primed into the tree (bc-java github #2414).
            byte[] corruptedEnc = Arrays.Clone(enc);
            corruptedEnc[76 + 2 * m] ^= 1;
            var ex = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(corruptedEnc));
            Assert.True(ex.Message.StartsWith("LMS private key tree cache inconsistent at node"));

            // An encoding with no trailing cache - what an older release writes - must still decode and sign
            // correctly.
            byte[] legacyEnc = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << h)
                .U32Str(seed.Length)
                .Bytes(seed)
                .Build();
            Assert.AreEqual(72, legacyEnc.Length);

            LmsPrivateKeyParameters legacy = LmsPrivateKeyParameters.GetInstance(legacyEnc);
            Assert.True(Lms.VerifySignature(publicKey, Lms.GenerateSign(legacy, msg), msg));
        }

        [Test]
        public void TestMalformedPrivateKeyTreeCache()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
            int m = sigParams.M;

            //
            // The number of nodes cached is capped (matching the interned-key table in the bc-java
            // implementation), so read the limit off a freshly generated key of the same parameters rather than
            // hard-coding it - the limit moves if that cap is resized.
            //
            byte[] sampleEnc = Lms.GenerateKeys(sigParams, otsParams, 0, I, seed).GetEncoded();
            int cacheCountLimit = ReadU32(sampleEnc, 40 + m);

            // A cache at the limit is accepted. The node values have to be the real ones: they are a
            // deterministic function of I, the master secret and the parameters, and are checked against each
            // other at decode (bc-java github #2414), so the sample key's own encoding is used rather than a
            // run of dummy bytes. The cache survives the round trip byte for byte.
            Assert.True(Arrays.AreEqual(sampleEnc, LmsPrivateKeyParameters.GetInstance(sampleEnc).GetEncoded()));

            // A cache whose count and length are in range but whose node values are not the ones the key
            // derives is refused rather than primed into the tree (bc-java github #2414).
            byte[] zeroed = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << sigParams.H)
                .U32Str(seed.Length)
                .Bytes(seed)
                .U32Str(cacheCountLimit)
                .Bytes(new byte[cacheCountLimit * m])
                .Build();
            var ex0 = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(zeroed));
            Assert.True(ex0.Message.StartsWith("LMS private key tree cache inconsistent at node"));

            byte[] beyondLimit = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << sigParams.H)
                .U32Str(seed.Length)
                .Bytes(seed)
                .U32Str(cacheCountLimit + 1)
                .Build();
            var ex1 = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(beyondLimit));
            Assert.True(ex1.Message.StartsWith("tree cache node count out of range"));

            byte[] truncated = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << sigParams.H)
                .U32Str(seed.Length)
                .Bytes(seed)
                .U32Str(cacheCountLimit)
                .Bytes(new byte[cacheCountLimit * m - 1])
                .Build();
            var ex2 = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(truncated));
            Assert.True(ex2.Message.StartsWith("tree cache length exceeded"));
        }

        /**
         * Every single-byte corruption of the tree cache is rejected at decode, and the one-time index q and
         * its limit maxQ are range checked. Both were unchecked before bc-java github #2414: a corrupt cache
         * primed into the tree yields signatures that do not verify, and a q outside the tree signs with a
         * one-time key the public key does not commit to.
         */
        [Test]
        public void TestPrivateKeyDecodeValidation()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
            int m = sigParams.M;

            LmsPrivateKeyParameters priv = Lms.GenerateKeys(sigParams, otsParams, 0, I, seed);
            byte[] enc = priv.GetEncoded();

            int countOff = 40 + ReadU32(enc, 36);
            int cacheCount = ReadU32(enc, countOff);
            int cacheOff = countOff + 4;
            Assert.True(cacheCount > 0, "expected a primed cache to corrupt");

            for (int r = 1; r <= cacheCount; r++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                corrupt[cacheOff + (r - 1) * m] ^= 0x01;
                var ex = Assert.Throws<InvalidDataException>(
                    () => LmsPrivateKeyParameters.GetInstance(corrupt), "no exception on corrupt cache node " + r);
                Assert.True(ex.Message.StartsWith("LMS private key tree cache inconsistent at node"));
            }

            int twoToH = 1 << sigParams.H;
            int[][] bad = { new int[]{ twoToH + 1, 1000 }, new int[]{ -1, twoToH },
                new int[]{ int.MinValue, twoToH }, new int[]{ 0, twoToH + 1 }, new int[]{ 0, -1 },
                new int[]{ 4, 3 } };
            for (int i = 0; i != bad.Length; i++)
            {
                byte[] bogus = Composer.Compose()
                    .U32Str(0)
                    .U32Str(sigParams.ID)
                    .U32Str(otsParams.ID)
                    .Bytes(I)
                    .U32Str(bad[i][0])
                    .U32Str(bad[i][1])
                    .U32Str(seed.Length)
                    .Bytes(seed)
                    .Build();
                var ex = Assert.Throws<InvalidDataException>(
                    () => LmsPrivateKeyParameters.GetInstance(bogus),
                    "no exception on q=" + bad[i][0] + " maxQ=" + bad[i][1]);
                Assert.True(ex.Message.StartsWith("LMS private key q/maxQ out of range"));
            }

            // the untouched encoding still decodes, and the cache survives the round trip
            Assert.True(Arrays.AreEqual(enc, LmsPrivateKeyParameters.GetInstance(enc).GetEncoded()));
        }

        /**
         * GetInstance(privEnc, pubEnc) cross-checks the cached root against the public key it is handed, which
         * catches a tree cache that is self-consistent but belongs to a different key. This check goes beyond
         * bc-java, which only applies it on the HSS entry point - the LMS path here is the one the PKCS#8
         * factory uses.
         */
        [Test]
        public void TestPrivateKeyCheckedAgainstSuppliedPublicKey()
        {
            byte[] seedA = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] IA = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] seedB = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            byte[] IB = Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;

            LmsPrivateKeyParameters keyA = Lms.GenerateKeys(sigParams, otsParams, 0, IA, seedA);
            LmsPrivateKeyParameters keyB = Lms.GenerateKeys(sigParams, otsParams, 0, IB, seedB);

            byte[] privA = keyA.GetEncoded();
            byte[] pubA = keyA.GetPublicKey().GetEncoded();
            byte[] pubB = keyB.GetPublicKey().GetEncoded();

            // matching pair: accepted, and the public key reported agrees
            LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(privA, pubA);
            Assert.True(Arrays.AreEqual(pubA, decoded.GetPublicKey().GetEncoded()));

            // another key's public key: refused
            var ex = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(privA, pubB));
            Assert.True(ex.Message.StartsWith("LMS private key tree cache does not match"));
        }

        /**
         * A private key encoding carrying an unknown LMS or LM-OTS type code is rejected with a clean parse
         * exception. The C# ParseByID helpers always did this - bc-java had to fix an NPE leak here - so this
         * pins the existing behaviour on the private key path.
         */
        [Test]
        public void TestMalformedPrivateKeyTypeCode()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            byte[] unknownSigType = Composer.Compose()
                .U32Str(0)
                .U32Str(0x7fffffff) // bogus LMS type code
                .U32Str(LMOtsParameters.sha256_n32_w4.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(32)
                .U32Str(seed.Length)
                .Bytes(seed)
                .Build();
            var ex1 = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(unknownSigType));
            Assert.True(ex1.Message.StartsWith("unknown LMS type code"));

            byte[] unknownOtsType = Composer.Compose()
                .U32Str(0)
                .U32Str(LMSigParameters.lms_sha256_n32_h5.ID)
                .U32Str(0x7fffffff) // bogus LM-OTS type code
                .Bytes(I)
                .U32Str(0)
                .U32Str(32)
                .U32Str(seed.Length)
                .Bytes(seed)
                .Build();
            var ex2 = Assert.Throws<InvalidDataException>(
                () => LmsPrivateKeyParameters.GetInstance(unknownOtsType));
            Assert.True(ex2.Message.StartsWith("unknown LM-OTS type code"));
        }

        private static int ReadU32(byte[] buf, int off) =>
            (buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
    }
}
