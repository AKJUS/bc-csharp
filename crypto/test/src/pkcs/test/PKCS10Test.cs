using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pkcs.Tests
{
    [TestFixture]
    public class Pkcs10Test
    {
        private static readonly byte[] EmptyExtensionsReq = Base64.Decode(
            "MIICVDCCATwCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKy8\n" +
            "4oC/QPFkRBE04LIA5njEulZx/EEh+J2spnThoRwk+oycYEVKp95NSfGTAoNjTwUv\n" +
            "TdB9c1PCPE1DmgZIVLEVvouB7sZbMbLSI0d//oMO/Wr/CZmvjPGB8DID7RJs0eqO\n" +
            "gLgSuyBVrwbcSKtxH4NrNDsS5IZXCcE3xzkxMDdz72m9jvIrl2ivi+YmJ7cJo3N+\n" +
            "DBEqHZW28oytOmVo+8zhxvnHb9w26GJEOxN5zYbiIVW2vU9OfeF9te+Rhnks43Pk\n" +
            "YDDP2U4hR7q0BYrdkeWdA1ReleYyn/haeAoIVLZMANIOXobiqASKqSusVq9tLD67\n" +
            "7TAywl5AVq8GOBzlXZUCAwEAAaAPMA0GCSqGSIb3DQEJDjEAMA0GCSqGSIb3DQEB\n" +
            "CwUAA4IBAQAXck62gJw1deVOLVFAwBNVNXgJarHtDg3pauHTHvN+pSbdOTe1aRzb\n" +
            "Tt4/govtuuGZsGWlUqiglLpl6qeS7Pe9m+WJwhH5yXnJ3yvy2Lc/XkeVQ0kt8uFg\n" +
            "30UyrgKng6LDgUGFjDSiFr3dK8S/iYpDu/qpl1bWJPWmfmnIXzZWWvBdUTKlfoD9\n" +
            "/NLIWINEzHQIBXGy2uLhutYOvDq0WDGOgtdFC8my/QajaJh5lo6mM/PlmcYjK286\n" +
            "EdGSIxdME7hoW/ljA5355S820QZDkYx1tI/Y/YaY5KVOntwfDQzQiwWZ2PtpTqSK\n" +
            "KYe2Ujb362yaERCE13DJC4Us9j8OOXcW\n");

        [Test]
        public void EmptyExtRequest()
        {
            Pkcs10CertificationRequest req = new Pkcs10CertificationRequest(EmptyExtensionsReq);

            try
            {
                req.GetRequestedExtensions();
                Assert.Fail("no exception thrown");
            }
            catch (InvalidOperationException e)
            {
                Assert.AreEqual("pkcs_9_at_extensionRequest present but has no value", e.Message);
            }
        }

        [Test]
        public void BrokenRequestWithDuplicateExtension()
        {
            string keyName = "RSA";
            int keySize = 2048;

            string sigName = "SHA256withRSA";

            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator(keyName);
            kpg.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            var attrs = new Dictionary<DerObjectIdentifier, string>();
            attrs.Add(X509Name.C, "AU");
            attrs.Add(X509Name.O, "The Legion of the Bouncy Castle");
            attrs.Add(X509Name.L, "Melbourne");
            attrs.Add(X509Name.ST, "Victoria");
            attrs.Add(X509Name.EmailAddress, "feedback-crypto@bouncycastle.org");

            var order = new List<DerObjectIdentifier>();
            order.Add(X509Name.C);
            order.Add(X509Name.O);
            order.Add(X509Name.L);
            order.Add(X509Name.ST);
            order.Add(X509Name.EmailAddress);

            X509Name subject = new X509Name(order, attrs);

            //
            // This is simulate the creation of a certification request with duplicate extensions.
            //

            GeneralName name1 = new GeneralName(GeneralName.DnsName, "bc1.local");
            GeneralName name2 = new GeneralName(GeneralName.DnsName, "bc2.local");

            Asn1EncodableVector v = new Asn1EncodableVector();
            Asn1EncodableVector e1 = new Asn1EncodableVector();
            e1.Add(X509Extensions.SubjectAlternativeName);
            e1.Add(new DerOctetString(new GeneralNames(name1).GetEncoded()));

            Asn1EncodableVector e2 = new Asn1EncodableVector();
            e2.Add(X509Extensions.SubjectAlternativeName);
            e2.Add(new DerOctetString(new GeneralNames(name2).GetEncoded()));

            v.Add(new DerSequence(e1));
            v.Add(new DerSequence(e2));

            AttributePkcs attribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                DerSet.FromElement(new DerSequence(v)));

            Pkcs10CertificationRequest req1 = new Pkcs10CertificationRequest(
                sigName,
                subject,
                kp.Public,
                new DerSet(attribute),
                kp.Private);


            // Round trip serialisation
            byte[] bytes = req1.GetEncoded();
            Pkcs10CertificationRequest req2 = new Pkcs10CertificationRequest(bytes);


            //
            // Check verification after round tripping serialisation.
            //

            if (!req2.Verify())
            {
                Assert.Fail(sigName + ": Failed Verify check.");
            }

            if (!req2.GetPublicKey().Equals(req1.GetPublicKey()))
            {
                Assert.Fail(keyName + ": Failed public key check.");
            }

            //
            // Disassemble the attributes with the duplicate extensions.
            //

            X509Extensions extensions = req2.GetRequestedExtensions();

            X509Extension returnedExtension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
            Asn1Sequence seq = Asn1Sequence.GetInstance(returnedExtension.GetParsedValue());

            //
            // Check expected order and value.
            //
            if (!GeneralName.GetInstance(seq[0]).Equals(name1))
            {
                Assert.Fail("expected name 1");
            }

            if (!GeneralName.GetInstance(seq[1]).Equals(name2))
            {
                Assert.Fail("expected name 2");
            }
        }

        /// <summary>
        /// Reported as a possible issue with Chinese characters but the error was only calling ReadPemObject
        /// </summary>
        [Test]
        public void GitHub_76()
        {
            string csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n"
                + "MIIBWDCB/wIBADCBnDELMAkGA1UEBhMCQ04xFTATBgNVBAgMDMOkwrjCrcOlwpvC\n"
                + "vTEVMBMGA1UEBwwMw6TCuMKtw6XCm8K9MRUwEwYDVQQKDAzDpMK4wq3DpcKbwr0x\n"
                + "FTATBgNVBAsMDMOkwrjCrcOlwpvCvTERMA8GA1UEAwwIdGVzdC5jb20xHjAcBgkq\n"
                + "hkiG9w0BCQEWD2NtczFAd29zaWduLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
                + "A0IABH5BKV5EksxpQSgs3N6KG58rUdFCEN00uIZLSfy7figQAYFE9oQhXC+5C59R\n"
                + "8g81DOsi8zfhOYexhvjLT+OUdemgADAKBggqhkjOPQQDAgNIADBFAiEA2se8iUlw\n"
                + "RwMAk/QCXEdCssnypRlxBOvFoetWwwl6a1MCID+OjMjdgSTk2VZidb7lpj15mLrE\n"
                + "WMy7tfeaFSuZfKIR\n"
                + "-----END CERTIFICATE REQUEST-----\n";

            Pkcs10CertificationRequest request;
            using (var pemReader = new PemReader(new StringReader(csrPem)))
            {
                // The original report used ReadPemObject here, which presumably was the actual error
                request = (Pkcs10CertificationRequest)pemReader.ReadObject();
            }

            Assert.True(request.Verify());

            var subject = request.GetCertificationRequestInfo().Subject.ToString();
            Assert.NotNull(subject);

            var publicKey = request.GetPublicKey();
            Assert.That(publicKey is ECPublicKeyParameters);
        }

        [Test]
        public void Basic()
        {
            IAsymmetricCipherKeyPairGenerator pGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            RsaKeyGenerationParameters genParam = new RsaKeyGenerationParameters(
                BigInteger.ValueOf(0x10001), new SecureRandom(), 512, 25);

            pGen.Init(genParam);

            AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();

            var attrs = new Dictionary<DerObjectIdentifier, string>();

            attrs.Add(X509Name.C, "AU");
            attrs.Add(X509Name.O, "The Legion of the Bouncy Castle");
            attrs.Add(X509Name.L, "Melbourne");
            attrs.Add(X509Name.ST, "Victoria");
            attrs.Add(X509Name.EmailAddress, "feedback-crypto@bouncycastle.org");

            X509Name subject = new X509Name(new List<DerObjectIdentifier>(attrs.Keys), attrs);

            Pkcs10CertificationRequest req1 = new Pkcs10CertificationRequest(
                "SHA1withRSA",
                subject,
                pair.Public,
                null,
                pair.Private);

            byte[] bytes = req1.GetEncoded();

            Pkcs10CertificationRequest req2 = new Pkcs10CertificationRequest(bytes);

            if (!req2.Verify())
            {
                Assert.Fail("Failed verify check.");
            }

            if (!req2.GetPublicKey().Equals(req1.GetPublicKey()))
            {
                Assert.Fail("Failed public key check.");
            }
        }
    }
}
