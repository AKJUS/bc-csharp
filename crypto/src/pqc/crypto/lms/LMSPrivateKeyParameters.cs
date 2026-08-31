using System;
using System.Collections.Concurrent;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsPrivateKeyParameters
        : LmsKeyParameters, ILmsContextBasedSigner
    {
        private static LmsPublicKeyParameters DerivePublicKey(LmsPrivateKeyParameters privateKey)
        {
            return new LmsPublicKeyParameters(privateKey.sigParameters, privateKey.otsParameters, privateKey.FindT(1),
                privateKey.I);
        }

        // The number of tree nodes eligible for the persisted cache (nodes 1 .. CacheTopLimit - 1: the top six
        // levels of the tree). Mirrors the interned-key table size in the bc-java implementation, which defines
        // the interchange format's cache-count limit.
        private const int CacheTopLimit = 64;

        private byte[] I;
        private readonly LMSigParameters sigParameters;
        private LMOtsParameters otsParameters;
        private int maxQ;
        private byte[] masterSecret;
        // TODO Java uses a WeakHashMap
        private ConcurrentDictionary<int, byte[]> tCache;
        private int maxCacheR;

        private int q;
        private readonly bool m_isPlaceholder;

        //
        // These are not final because they can be generated.
        // They also do not need to be persisted.
        //
        private LmsPublicKeyParameters m_publicKey;

        public LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret)
            : this(lmsParameter, otsParameters, q, I, maxQ, masterSecret, false)
        {
        }

        internal LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret, bool isPlaceholder)
            : base(true)
        {
            this.sigParameters = lmsParameter;
            this.otsParameters = otsParameters;
            this.q = q;
            this.I = Arrays.Clone(I);
            this.maxQ = maxQ;
            this.masterSecret = Arrays.Clone(masterSecret);
            this.maxCacheR = 1 << (sigParameters.H + 1);
            this.tCache = new ConcurrentDictionary<int, byte[]>();
            this.m_isPlaceholder = isPlaceholder;
        }

        private LmsPrivateKeyParameters(LmsPrivateKeyParameters parent, int q, int maxQ)
            : base(true)
        {
            this.sigParameters = parent.sigParameters;
            this.otsParameters = parent.otsParameters;
            this.q = q;
            this.I = parent.I;
            this.maxQ = maxQ;
            this.masterSecret = parent.masterSecret;
            this.maxCacheR = 1 << sigParameters.H;
            this.tCache = parent.tCache;
            this.m_publicKey = parent.m_publicKey;
        }

        public static LmsPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc) =>
            Parse(privEnc, 0, privEnc.Length, LmsPublicKeyParameters.Parse(pubEnc));

        public static LmsPrivateKeyParameters GetInstance(object src)
        {
            if (src is LmsPrivateKeyParameters lmsPrivateKeyParameters)
                return lmsPrivateKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return Parse(stream);

            if (src is byte[] bytes)
                return Parse(bytes);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsPrivateKeyParameters Parse(BinaryReader binaryReader)
        {
            LmsPrivateKeyParameters key = ParseCore(binaryReader);

            //
            // Anything after the master secret is a cache of the top of the Merkle tree (see GetEncoded). Priming
            // it here means the first signature made after the key is decoded does not have to rebuild the whole
            // tree, which otherwise costs about as much as key generation. For a standalone key the cache is
            // optional trailing data rather than a new version, matching the bc-java interchange format - at the
            // cost of it being absent rather than malformed when a stream supplies no more bytes. Component keys
            // inside an HSS private key share their stream with the keys and signatures that follow, so "more
            // data" means nothing there - they are read via ReadKey, where the enclosing HSS encoding's version
            // dictates whether the cache field is present (bc-java github #2365).
            //
            var stream = binaryReader.BaseStream;
            if (stream.CanSeek && stream.Position < stream.Length)
            {
                ReadTreeCache(binaryReader, key);
            }

            return key;
        }

        /**
         * Read a component key from a stream shared with the other keys and signatures of an HSS private key.
         * Unlike the standalone Parse entry point, whether the tree-cache field is present is dictated by the
         * caller - from the enclosing HSS encoding's version - rather than inferred from the stream having more
         * data, which is meaningless mid-stream.
         */
        internal static LmsPrivateKeyParameters ReadKey(BinaryReader binaryReader, bool withCache)
        {
            LmsPrivateKeyParameters key = ParseCore(binaryReader);

            if (withCache)
            {
                ReadTreeCache(binaryReader, key);
            }

            return key;
        }

        private static LmsPrivateKeyParameters ParseCore(BinaryReader binaryReader)
        {
            int version = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (version != 0)
                throw new Exception("unknown version for LMS private key");

            LMSigParameters sigParameter = LMSigParameters.ParseByID(binaryReader);
            LMOtsParameters otsParameter = LMOtsParameters.ParseByID(binaryReader);

            byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

            int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

            int maxQ = BinaryReaders.ReadInt32BigEndian(binaryReader);

            int l = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (l < 0)
                throw new Exception("secret length less than zero");

            byte[] masterSecret = BinaryReaders.ReadBytesFully(binaryReader, l);

            return new LmsPrivateKeyParameters(sigParameter, otsParameter, q, I, maxQ, masterSecret);
        }

        private static void ReadTreeCache(BinaryReader binaryReader, LmsPrivateKeyParameters key)
        {
            int cacheCount = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (cacheCount < 0 || cacheCount >= CacheTopLimit)
                throw new InvalidDataException($"tree cache node count out of range: {cacheCount}");

            int m = key.sigParameters.M;
            var stream = binaryReader.BaseStream;
            if (stream.CanSeek && (long)cacheCount * m > stream.Length - stream.Position)
                throw new InvalidDataException($"tree cache length exceeded {stream.Length - stream.Position}");

            // Entries match the state a freshly generated key reaches after its public key has been derived.
            for (int r = 1; r <= cacheCount; r++)
            {
                key.tCache[r] = BinaryReaders.ReadBytesFully(binaryReader, m);
            }
        }

        internal static LmsPrivateKeyParameters Parse(Stream stream) =>
            BinaryReaders.Parse(Parse, stream, leaveOpen: true);

        internal static LmsPrivateKeyParameters Parse(byte[] buf) => Parse(buf, 0, buf.Length);

        internal static LmsPrivateKeyParameters Parse(byte[] buf, int off, int len) =>
            BinaryReaders.Parse(Parse, buf, off, len, "LMS private key");

        internal static LmsPrivateKeyParameters Parse(byte[] buf, int off, int len, LmsPublicKeyParameters publicKey)
        {
            LmsPrivateKeyParameters pKey = Parse(buf, off, len);
            pKey.m_publicKey = publicKey;
            return pKey;
        }

        internal LMOtsPrivateKey GetCurrentOtsKey()
        {
            lock (this)
            {
                if (q >= maxQ)
                    // TODO ExhaustedPrivateKeyException
                    throw new Exception("ots private keys expired");

                return new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
            }
        }

        /**
         * Return the key index (the q value).
         *
         * @return private key index number.
         */
        public int GetIndex()
        {
            lock (this)
                return q;
        }

        internal void IncIndex()
        {
            lock (this)
            {
                q++;
            }
        }

        public LmsContext GenerateLmsContext()
        {
            // Step 1.
            LMSigParameters lmsParameter = SigParameters;

            // Step 2
            int h = lmsParameter.H;
            int q = GetIndex();
            LMOtsPrivateKey otsPk = GetNextOtsPrivateKey();

            int i = 0;
            int r = (1 << h) + q;
            byte[][] path = new byte[h][];

            while (i < h)
            {
                int tmp = (r / (1 << i)) ^ 1;

                path[i++] = FindT(tmp);
            }

            return otsPk.GetSignatureContext(sigParameters, path);
        }

        public byte[] GenerateSignature(LmsContext context)
        {
            try
            {
                return Lms.GenerateSign(context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new Exception($"unable to encode signature: {e.Message}", e);
            }
        }

        internal LMOtsPrivateKey GetNextOtsPrivateKey()
        {
            if (m_isPlaceholder)
                throw new Exception("placeholder only");

            lock (this)
            {
                if (q >= maxQ)
                    throw new Exception("ots private key exhausted");

                LMOtsPrivateKey otsPrivateKey = new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
                IncIndex();
                return otsPrivateKey;
            }
        }

        /**
         * Return a key that can be used usageCount times.
         * <p>
         * Note: this will use the range [index...index + usageCount) for the current key.
         * </p>
         *
         * @param usageCount the number of usages the key should have.
         * @return a key based on the current key that can be used usageCount times.
         */
        public LmsPrivateKeyParameters ExtractKeyShard(int usageCount)
        {
            lock (this)
            {
                if (usageCount < 0)
                    throw new ArgumentOutOfRangeException(nameof(usageCount), "cannot be negative");
                if (usageCount > maxQ - q)
                    throw new ArgumentException("exceeds usages remaining", nameof(usageCount));

                int shardIndex = q;
                int shardIndexLimit = q + usageCount;

                // Move this key's index along
                q = shardIndexLimit;

                return new LmsPrivateKeyParameters(this, shardIndex, shardIndexLimit);
            }
        }

        [Obsolete("Use 'SigParameters' instead")]
        public LMSigParameters GetSigParameters() => sigParameters;

        public LMSigParameters SigParameters => sigParameters;

        [Obsolete("Use 'OtsParameters' instead")]
        public LMOtsParameters GetOtsParameters() => otsParameters;

        public LMOtsParameters OtsParameters => otsParameters;

        public byte[] GetI() => Arrays.Clone(I);

        public byte[] GetMasterSecret() => Arrays.Clone(masterSecret);

        public int IndexLimit => maxQ;

        // TODO[api] Only needs 'int'
        public long GetUsagesRemaining() => IndexLimit - GetIndex();

        public LmsPublicKeyParameters GetPublicKey()
        {
            if (m_isPlaceholder)
                throw new Exception("placeholder only");

            return Objects.EnsureSingletonInitialized(ref m_publicKey, this, DerivePublicKey);
        }

        internal byte[] FindT(int r)
        {
            if (r >= maxCacheR)
                return CalcT(r);

            return tCache.GetOrAdd(r, CalcT);
        }

        private byte[] CalcT(int r)
        {
            var tDigest = LmsUtilities.GetDigest(this.sigParameters);

            int h = sigParameters.H;

            int twoToh = 1 << h;

            byte[] T = new byte[tDigest.GetDigestSize()];

            // r is a base 1 index.

            if (r >= twoToh)
            {
                LmsUtilities.ByteArray(I, tDigest);
                LmsUtilities.U32Str(r, tDigest);
                LmsUtilities.U16Str((short)Lms.D_LEAF, tDigest);
                //
                // These can be pre generated at the time of key generation and held within the private key.
                // However it will cost memory to have them stick around.
                //
                byte[] K = LMOts.LmsOtsGeneratePublicKey(otsParameters, I, r - twoToh, masterSecret);

                LmsUtilities.ByteArray(K, tDigest);
            }
            else
            {
                byte[] t2r = FindT(2 * r);
                byte[] t2rPlus1 = FindT(2 * r + 1);

                LmsUtilities.ByteArray(I, tDigest);
                LmsUtilities.U32Str(r, tDigest);
                LmsUtilities.U16Str((short)Lms.D_INTR, tDigest);
                LmsUtilities.ByteArray(t2r, tDigest);
                LmsUtilities.ByteArray(t2rPlus1, tDigest);
            }

            tDigest.DoFinal(T, 0);
            return T;
        }

        // TODO[api] Fix parameter name
        public override bool Equals(object o)
        {
            if (this == o)
                return true;

            return o is LmsPrivateKeyParameters that
                && this.q == that.q
                && this.maxQ == that.maxQ
                && Arrays.AreEqual(this.I, that.I)
                && Objects.Equals(this.sigParameters, that.sigParameters)
                && Objects.Equals(this.otsParameters, that.otsParameters)
                && Arrays.AreEqual(this.masterSecret, that.masterSecret);
        }

        public override int GetHashCode()
        {
            int result = q;
            result = 31 * result + maxQ;
            result = 31 * result + Arrays.GetHashCode(I);
            result = 31 * result + Objects.GetHashCode(sigParameters);
            result = 31 * result + Objects.GetHashCode(otsParameters);
            result = 31 * result + Arrays.GetHashCode(masterSecret);
            return result;
        }

        public override byte[] GetEncoded()
        {
            //
            // NB there is no formal specification for the encoding of private keys.
            // It is implementation dependent.
            //
            // Format:
            //     version u32                 (0)
            //     type u32
            //     otstype u32
            //     I u8x16
            //     q u32
            //     maxQ u32
            //     master secret Length u32
            //     master secret u8[]
            //     tree cache node count u32   (n; the top-of-tree nodes 1..n) - optional
            //     tree cache nodes u8[]       (n * SigParameters.M bytes) - optional
            //
            // The tree cache carries the top of the Merkle tree so that the first signature made after the key
            // is decoded does not have to rebuild the whole tree - which otherwise costs about as much as key
            // generation (see bc-java github #2365). The nodes are a deterministic function of I, the master
            // secret and the parameters and are independent of q, so persisting them leaks nothing the (already
            // encoded) master secret does not. The cache is appended after the master secret rather than
            // announced by a new version number, matching the bc-java interchange format, whose pre-cache
            // decoders stop at the master secret and ignore the trailing bytes.
            //

            int cacheTop = System.Math.Min(CacheTopLimit, maxCacheR);

            Composer composer = Composer.Compose()
                .U32Str(0) // version
                .U32Str(sigParameters.ID) // type
                .U32Str(otsParameters.ID) // ots type
                .Bytes(I) // I at 16 bytes
                .U32Str(q) // q
                .U32Str(maxQ) // maximum q
                .U32Str(masterSecret.Length) // length of master secret.
                .Bytes(masterSecret) // the master secret
                .U32Str(cacheTop - 1); // number of cached tree nodes (nodes 1 .. cacheTop-1)

            for (int r = 1; r < cacheTop; r++)
            {
                composer.Bytes(FindT(r)); // top-of-tree node r
            }

            return composer.Build();
        }
    }
}
