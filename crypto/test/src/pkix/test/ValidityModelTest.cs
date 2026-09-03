using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.IsisMtt;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix.Tests
{
    /// <summary>
    /// Tests that <see cref="PkixCertPathValidator"/> honours <see cref="PkixParameters.Date"/> under both
    /// <see cref="PkixParameters.PkixValidityModel"/> (shell model) and
    /// <see cref="PkixParameters.ChainValidityModel"/>.
    /// </summary>
    /// <remarks>
    /// In the shell model every certificate in the path is checked against the validation date. In the chain model
    /// only the end-entity certificate is checked against the validation date; each CA certificate is checked at
    /// the time its subordinate certificate was issued, taken from the subordinate's NotBefore or, for the
    /// end-entity certificate, its ISIS-MTT dateOfCertGen extension when present. See github #246.
    /// </remarks>
    [TestFixture]
    public class ValidityModelTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly DateTime D2019 = Utc(2019, 1, 1);
        private static readonly DateTime D2020 = Utc(2020, 1, 1);
        private static readonly DateTime D2021_03 = Utc(2021, 3, 1);
        private static readonly DateTime D2021_05 = Utc(2021, 5, 1);
        private static readonly DateTime D2021_06 = Utc(2021, 6, 1);
        private static readonly DateTime D2021_07 = Utc(2021, 7, 1);
        private static readonly DateTime D2030 = Utc(2030, 1, 1);
        private static readonly DateTime D2040 = Utc(2040, 1, 1);

        [Test]
        public void ShellModelChecksEndEntityAgainstDate()
        {
            var rootKp = GenerateKeyPair();
            var interKp = GenerateKeyPair();
            var eeKp = GenerateKeyPair();

            var root = MakeCert("CN=Root", rootKp.Public, "CN=Root", rootKp.Private, D2020, D2040, true, null);
            var inter = MakeCert("CN=Inter", interKp.Public, "CN=Root", rootKp.Private, D2020, D2040, true, null);
            // EE valid only during 2021-03 .. 2021-06
            var ee = MakeCert("CN=EE", eeKp.Public, "CN=Inter", interKp.Private, D2021_03, D2021_06, false, null);

            // Inside the EE window
            Validate(root, inter, ee, D2021_05, PkixParameters.PkixValidityModel);

            // After the EE window
            ExpectFailure<CertificateExpiredException>(root, inter, ee, D2021_07, PkixParameters.PkixValidityModel);

            // Before the EE window
            ExpectFailure<CertificateNotYetValidException>(root, inter, ee, D2020, PkixParameters.PkixValidityModel);

            // No Date set => current time (after 2021-06) => expired
            ExpectFailure<CertificateExpiredException>(root, inter, ee, null, PkixParameters.PkixValidityModel);
        }

        [Test]
        public void ChainModelChecksIssuerAtSubordinateNotBefore()
        {
            var rootKp = GenerateKeyPair();
            var interKp = GenerateKeyPair();
            var eeKp = GenerateKeyPair();

            var root = MakeCert("CN=Root", rootKp.Public, "CN=Root", rootKp.Private, D2020, D2040, true, null);
            // Intermediate expires 2021-06
            var inter = MakeCert("CN=Inter", interKp.Public, "CN=Root", rootKp.Private, D2020, D2021_06, true, null);
            // EE issued 2021-03 (while inter still valid), valid until 2030
            var ee = MakeCert("CN=EE", eeKp.Public, "CN=Inter", interKp.Private, D2021_03, D2030, false, null);

            // Shell model at 2021-07: intermediate has expired
            ExpectFailure<CertificateExpiredException>(root, inter, ee, D2021_07, PkixParameters.PkixValidityModel);

            // Chain model at 2021-07: EE checked at Date, intermediate checked at EE.NotBefore
            Validate(root, inter, ee, D2021_07, PkixParameters.ChainValidityModel);

            // Chain model with Date after EE expiry: EE itself is still checked against Date
            ExpectFailure<CertificateExpiredException>(root, inter, ee, D2040, PkixParameters.ChainValidityModel);
        }

        [Test]
        public void ChainModelUsesDateOfCertGenWhenPresent()
        {
            var rootKp = GenerateKeyPair();
            var interKp = GenerateKeyPair();
            var eeKp = GenerateKeyPair();

            var root = MakeCert("CN=Root", rootKp.Public, "CN=Root", rootKp.Private, D2019, D2040, true, null);
            // Intermediate valid from 2020
            var inter = MakeCert("CN=Inter", interKp.Public, "CN=Root", rootKp.Private, D2020, D2040, true, null);

            // EE NotBefore (2019) predates inter.NotBefore; without dateOfCertGen the intermediate is not yet valid
            var eeNoExt = MakeCert("CN=EE", eeKp.Public, "CN=Inter", interKp.Private, D2019, D2030, false, null);
            ExpectFailure<CertificateNotYetValidException>(root, inter, eeNoExt, D2021_07,
                PkixParameters.ChainValidityModel);

            // Same EE with dateOfCertGen = 2021-05: intermediate is checked at 2021-05 instead
            var eeExt = MakeCert("CN=EE", eeKp.Public, "CN=Inter", interKp.Private, D2019, D2030, false, D2021_05);
            Validate(root, inter, eeExt, D2021_07, PkixParameters.ChainValidityModel);
        }

        private static DateTime Utc(int year, int month, int day) =>
            new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc);

        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new KeyGenerationParameters(Random, 1024));
            return kpg.GenerateKeyPair();
        }

        private static X509Certificate MakeCert(string subject, AsymmetricKeyParameter subjectKey, string issuer,
            AsymmetricKeyParameter issuerKey, DateTime notBefore, DateTime notAfter, bool isCa,
            DateTime? dateOfCertGen)
        {
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(new BigInteger(63, Random).Add(BigInteger.One));
            gen.SetIssuerDN(new X509Name(issuer));
            gen.SetSubjectDN(new X509Name(subject));
            gen.SetNotBefore(notBefore);
            gen.SetNotAfter(notAfter);
            gen.SetPublicKey(subjectKey);
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));
            if (dateOfCertGen.HasValue)
            {
                gen.AddExtension(IsisMttObjectIdentifiers.IdIsisMttATDateOfCertGen, false,
                    new Asn1GeneralizedTime(dateOfCertGen.Value));
            }
            return gen.Generate(new Asn1SignatureFactory("SHA256withRSA", issuerKey));
        }

        private static void Validate(X509Certificate root, X509Certificate inter, X509Certificate ee,
            DateTime? date, int validityModel)
        {
            var certPath = new PkixCertPath(new List<X509Certificate>{ ee, inter });

            var pkixParams = new PkixParameters(new HashSet<TrustAnchor>{ new TrustAnchor(root, null) });
            pkixParams.Date = date;
            pkixParams.ValidityModel = validityModel;
            pkixParams.IsRevocationEnabled = false;

            new PkixCertPathValidator().Validate(certPath, pkixParams);
        }

        private static void ExpectFailure<TCause>(X509Certificate root, X509Certificate inter, X509Certificate ee,
            DateTime? date, int validityModel)
            where TCause : Exception
        {
            try
            {
                Validate(root, inter, ee, date, validityModel);
            }
            catch (PkixCertPathValidatorException e)
            {
                Exception cause = e;
                while (cause != null)
                {
                    if (cause is TCause)
                        return;

                    cause = cause.InnerException;
                }
                Assert.Fail("unexpected failure: " + e);
            }
            Assert.Fail("expected failure with cause " + typeof(TCause).Name);
        }
    }
}
