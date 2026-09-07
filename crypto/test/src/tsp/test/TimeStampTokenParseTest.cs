using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tsp.Tests
{
    /// <summary>
    /// A well-formed RFC 3161 TimeStampResp whose embedded token is malformed - in its TSTInfo content or in the number
    /// of SignerInfos carrying it - must be reported through the documented <see cref="TspException"/> of
    /// <see cref="TimeStampResponse"/>, not as an unchecked exception from the internal ASN.1 parse.
    /// </summary>
    [TestFixture]
    public class TimeStampTokenParseTest
    {
        // empty SEQUENCE - fewer elements than TSTInfo's five mandatory fields
        [Test]
        public void EmptySequenceTstInfo() => CheckRejected(DerSequence.Empty.GetEncoded());

        // valid DER, wrong type - ASN1Sequence.getInstance rejects a non-SEQUENCE
        [Test]
        public void NonSequenceTstInfo() => CheckRejected(DerInteger.Zero.GetEncoded());

        // structurally broken DER - length octet promises more than is present
        [Test]
        public void TruncatedTstInfo() => CheckRejected(new byte[]{ 0x30, 0x05, 0x02, 0x01 });

        // RFC 3161 sec. 2.4.2 gives TSTInfo ten fields at most
        [Test]
        public void OversizeTstInfo()
        {
            Asn1Encodable[] elements = new Asn1Encodable[11];

            for (int i = 0; i != elements.Length; ++i)
            {
                elements[i] = DerInteger.One;
            }

            CheckRejected(new DerSequence(elements).GetEncoded());
        }

        // RFC 3161 sec. 2.4.2: the token must carry exactly the TSA signature
        [Test]
        public void NoSigners() => CheckRejected(WellFormedTstInfo(), DerSet.Empty);

        [Test]
        public void MultipleSigners() => CheckRejected(WellFormedTstInfo(), new DerSet(SignerInfo(), SignerInfo()));

        private void CheckRejected(byte[] tstInfoContent) => CheckRejected(tstInfoContent, new DerSet(SignerInfo()));

        private void CheckRejected(byte[] tstInfoContent, Asn1Set signerInfos)
        {
            byte[] resp = MakeResponse(tstInfoContent, signerInfos);

            try
            {
                new TimeStampResponse(resp);
                Assert.Fail("malformed timestamp token accepted");
            }
            catch (TspException)
            {
                // expected - the parse failure is surfaced as the declared checked exception
            }
        }

        private static byte[] WellFormedTstInfo()
        {
            return new DerSequence(new Asn1Encodable[]{
                DerInteger.One,
                Asn1.Pkcs.PkcsObjectIdentifiers.IdCTTstInfo,
                new DerSequence(Sha256(), DerOctetString.WithContents(new byte[32])),
                DerInteger.One,
                new Asn1GeneralizedTime("20260101000000Z") }).GetEncoded();
        }

        private static AlgorithmIdentifier Sha256() => new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);

        private static SignerInfo SignerInfo()
        {
            SignerIdentifier sid = new SignerIdentifier(
                new IssuerAndSerialNumber(new X509Name("CN=Test TSA"), BigIntegers.One));

            return new SignerInfo(sid, Sha256(), (Asn1Set)null,
                new AlgorithmIdentifier(Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption),
                DerOctetString.WithContents(new byte[]{ 1, 2, 3, 4 }), (Asn1Set)null);
        }

        private static byte[] MakeResponse(byte[] tstInfoContent, Asn1Set signerInfos)
        {
            ContentInfo encapContentInfo = new ContentInfo(
                Asn1.Pkcs.PkcsObjectIdentifiers.IdCTTstInfo, DerOctetString.WithContents(tstInfoContent));

            SignedData signedData = new SignedData(new DerSet(Sha256()), encapContentInfo, null, null, signerInfos);

            ContentInfo token = new ContentInfo(Asn1.Pkcs.PkcsObjectIdentifiers.SignedData, signedData);

            TimeStampResp resp = new TimeStampResp(new PkiStatusInfo((int)PkiStatus.Granted), token);

            return resp.GetEncoded();
        }
    }
}
