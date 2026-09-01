using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class RsaKeyParametersTest
    {
        // Real RSA test-vector moduli (also used in RSATest), needed since RsaKeyParameters validates its
        // modulus (rejects small prime factors, requires it be composite, etc).
        private static readonly BigInteger Modulus1 = new BigInteger(
            "b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2" +
            "b6543165a040c606887420e33d91ed7ed7", 16);
        private static readonly BigInteger Modulus2 = new BigInteger(
            "0100000000000000000000000000000000bba2d15dbb303c8a21c5ebbcbae52b7125087920dd7cdf358ea119fd66f" +
            "b064012ec8ce692f0a0b8e8321b041acd40b7", 16);

        private static readonly BigInteger Exponent1 = new BigInteger("11", 16);
        private static readonly BigInteger Exponent2 = new BigInteger("03", 16);

        [Test]
        public void GetHashCode_DiffersWhenOnlyExponentDiffers()
        {
            var a = new RsaKeyParameters(false, Modulus1, Exponent1);
            var b = new RsaKeyParameters(false, Modulus1, Exponent2);

            Assert.That(a.Equals(b), Is.False);
            Assert.That(a.GetHashCode(), Is.Not.EqualTo(b.GetHashCode()));
        }

        [Test]
        public void GetHashCode_DiffersWhenOnlyModulusDiffers()
        {
            var a = new RsaKeyParameters(false, Modulus1, Exponent1);
            var b = new RsaKeyParameters(false, Modulus2, Exponent1);

            Assert.That(a.Equals(b), Is.False);
            Assert.That(a.GetHashCode(), Is.Not.EqualTo(b.GetHashCode()));
        }

        [Test]
        public void GetHashCode_MatchesWhenEqual()
        {
            var a = new RsaKeyParameters(false, Modulus1, Exponent1);
            var b = new RsaKeyParameters(false, Modulus1, Exponent1);

            Assert.That(a.Equals(b), Is.True);
            Assert.That(a.GetHashCode(), Is.EqualTo(b.GetHashCode()));
        }
    }
}
