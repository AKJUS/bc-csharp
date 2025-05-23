using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class SubjectKeyIdentifierTest
        : SimpleTest
    {
        private static readonly byte[] pubKeyInfo = Base64.Decode(
            "MFgwCwYJKoZIhvcNAQEBA0kAMEYCQQC6wMMmHYMZszT/7bNFMn+gaZoiWJLVP8ODRuu1C2jeAe" +
            "QpxM+5Oe7PaN2GNy3nBE4EOYkB5pMJWA0y9n04FX8NAgED");

        private static readonly byte[] shaID = Hex.Decode("d8128a06d6c2feb0865994a2936e7b75b836a021");
        private static readonly byte[] shaTruncID = Hex.Decode("436e7b75b836a021");

        public override string Name => "SubjectKeyIdentifier";

        public override void PerformTest()
        {
            SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(pubKeyInfo);
            SubjectKeyIdentifier ski = X509ExtensionUtilities.CreateSubjectKeyIdentifier(pubInfo);

            if (!Arrays.AreEqual(shaID, ski.GetKeyIdentifier()))
            {
                Fail("SHA-1 ID does not match");
            }

            ski = SubjectKeyIdentifier.CreateTruncatedSha1KeyIdentifier(pubInfo);

            if (!Arrays.AreEqual(shaTruncID, ski.GetKeyIdentifier()))
            {
                Fail("truncated SHA-1 ID does not match");
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
