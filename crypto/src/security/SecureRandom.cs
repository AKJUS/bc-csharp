using System;
using System.Threading;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Security
{
    public class SecureRandom
        : Random
    {
        private static long counter = DateTime.UtcNow.Ticks;

        private static long NextCounterValue()
        {
            return Interlocked.Increment(ref counter);
        }

        private static readonly SecureRandom MasterRandom = new SecureRandom(new CryptoApiRandomGenerator());
        internal static readonly SecureRandom ArbitraryRandom = new SecureRandom(new VmpcRandomGenerator(), 16);

        private static DigestRandomGenerator CreatePrng(string digestName, bool autoSeed)
        {
            IDigest digest = DigestUtilities.GetDigest(digestName);
            if (digest == null)
                return null;
            DigestRandomGenerator prng = new DigestRandomGenerator(digest);
            if (autoSeed)
            {
                AutoSeed(prng, 2 * digest.GetDigestSize());
            }
            return prng;
        }

        public static byte[] GetNextBytes(SecureRandom secureRandom, int length)
        {
            byte[] result = new byte[length];
            secureRandom.NextBytes(result);
            return result;
        }

        /// <summary>
        /// Create and auto-seed an instance based on the given algorithm.
        /// </summary>
        /// <remarks>Equivalent to GetInstance(algorithm, true)</remarks>
        /// <param name="algorithm">e.g. "SHA256PRNG"</param>
        public static SecureRandom GetInstance(string algorithm)
        {
            return GetInstance(algorithm, true);
        }

        /// <summary>
        /// Create an instance based on the given algorithm, with optional auto-seeding
        /// </summary>
        /// <param name="algorithm">e.g. "SHA256PRNG"</param>
        /// <param name="autoSeed">If true, the instance will be auto-seeded.</param>
        public static SecureRandom GetInstance(string algorithm, bool autoSeed)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (algorithm.EndsWith("PRNG", StringComparison.OrdinalIgnoreCase))
            {
                string digestName = algorithm.Substring(0, algorithm.Length - "PRNG".Length);

                DigestRandomGenerator prng = CreatePrng(digestName, autoSeed);
                if (prng != null)
                    return new SecureRandom(prng);
            }

            throw new ArgumentException("Unrecognised PRNG algorithm: " + algorithm, "algorithm");
        }

        protected readonly IRandomGenerator generator;

        public SecureRandom()
            : this(CreatePrng("SHA256", true))
        {
        }

        /// <summary>Use the specified instance of IRandomGenerator as random source.</summary>
        /// <remarks>
        /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
        /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
        /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
        /// implementation.
        /// </remarks>
        /// <param name="generator">The source to generate all random bytes from.</param>
        public SecureRandom(IRandomGenerator generator)
            : base(0)
        {
            this.generator = generator;
        }

        public SecureRandom(IRandomGenerator generator, int autoSeedLengthInBytes)
            : base(0)
        {
            AutoSeed(generator, autoSeedLengthInBytes);

            this.generator = generator;
        }

        public virtual byte[] GenerateSeed(int length)
        {
            return GetNextBytes(MasterRandom, length);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void GenerateSeed(Span<byte> seed)
        {
            MasterRandom.NextBytes(seed);
        }
#endif

        public virtual void SetSeed(byte[] seed)
        {
            generator.AddSeedMaterial(seed);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void SetSeed(Span<byte> seed)
        {
            generator.AddSeedMaterial(seed);
        }
#endif

        public virtual void SetSeed(long seed)
        {
            generator.AddSeedMaterial(seed);
        }

        public override int Next()
        {
            return NextInt() & int.MaxValue;
        }

        public override int Next(int maxValue)
        {
            if (maxValue < 2)
            {
                if (maxValue < 0)
                    throw new ArgumentOutOfRangeException(nameof(maxValue), "cannot be negative");

                return 0;
            }

            int bits;

            // Test whether maxValue is a power of 2
            if ((maxValue & (maxValue - 1)) == 0)
            {
                bits = NextInt() & int.MaxValue;
                return (int)(((long)bits * maxValue) >> 31);
            }

            int result;
            do
            {
                bits = NextInt() & int.MaxValue;
                result = bits % maxValue;
            }
            while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

            return result;
        }

        public override int Next(int minValue, int maxValue)
        {
            if (maxValue <= minValue)
            {
                if (maxValue == minValue)
                    return minValue;

                throw new ArgumentException("maxValue cannot be less than minValue");
            }

            int diff = maxValue - minValue;
            if (diff > 0)
                return minValue + Next(diff);

            for (;;)
            {
                int i = NextInt();

                if (i >= minValue && i < maxValue)
                    return i;
            }
        }

        public override void NextBytes(byte[] buf)
        {
            generator.NextBytes(buf);
        }

        public virtual void NextBytes(byte[] buf, int off, int len)
        {
            generator.NextBytes(buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void NextBytes(Span<byte> buffer)
        {
            if (generator != null)
            {
                generator.NextBytes(buffer);
            }
            else
            {
                byte[] tmp = new byte[buffer.Length];
                NextBytes(tmp);
                tmp.CopyTo(buffer);
            }
        }
#endif

        private static readonly double DoubleScale = 1.0 / Convert.ToDouble(1L << 53);

        public override double NextDouble()
        {
            ulong x = (ulong)NextLong() >> 11;

            return Convert.ToDouble(x) * DoubleScale;
        }

        public virtual int NextInt()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = stackalloc byte[4];
#else
            byte[] bytes = new byte[4];
#endif
            NextBytes(bytes);
            return (int)Pack.BE_To_UInt32(bytes);
        }

        public virtual long NextLong()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = stackalloc byte[8];
#else
            byte[] bytes = new byte[8];
#endif
            NextBytes(bytes);
            return (long)Pack.BE_To_UInt64(bytes);
        }

        private static void AutoSeed(IRandomGenerator generator, int seedLength)
        {
            generator.AddSeedMaterial(NextCounterValue());

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> seed = seedLength <= 128
                ? stackalloc byte[seedLength]
                : new byte[seedLength];
#else
            byte[] seed = new byte[seedLength];
#endif
            MasterRandom.NextBytes(seed);
            generator.AddSeedMaterial(seed);
        }
    }
}
